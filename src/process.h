#pragma once

#include <wtypes.h>
#include <TlHelp32.h>
#include <string>
#include <fstream>
#include <filesystem>

#include "util.h"
#include "api_set.h"

#include "memory-interfaces/windows_api.h"
#include "memory-interfaces/driver.h"

namespace memlite {

	struct module_t
	{
		void* base;
		size_t size;
	};

	template <typename memory_interface = interfaces::windows_api>
	class process
	{
	private:
		DWORD m_pid;
		memory_interface m_interface;
		bool m_valid = false;

		std::unordered_map<std::wstring, module_t> m_modules = {};

	public:
		explicit process( DWORD pid ) : m_pid( pid ) { if ( m_interface.attach( pid ) ) m_valid = true; }
		~process() { m_interface.detach(); }

		inline bool valid() { return m_valid; }
		inline memory_interface& get_memory_interface() { return m_interface; }

		bool read( void* address, void* buffer, size_t size ) { return m_interface.read( address, buffer, size ); }
		bool try_read( void* address, void* buffer, size_t size, size_t max_attempts = 50 );
		bool write( void* address, void* buffer, size_t size ) { return m_interface.write( address, buffer, size ); }
		void* alloc( void* address, size_t size, DWORD allocation_type, DWORD protect ) { return m_interface.alloc( address, size, allocation_type, protect ); }

		template<typename T>
		inline T read( void* address )
		{
			T buffer{};
			read( address, &buffer, sizeof( T ) );
			return buffer;
		}

		template<typename T>
		inline bool write( void* address, T value )
		{
			return write( address, &value, sizeof( T ) );
		}

		inline void* alloc( size_t size, DWORD allocation_type, DWORD protect ) { return m_interface.alloc( nullptr, size, allocation_type, protect ); }

		module_t* get_module( const std::wstring& name );
		bool load_image( const char* filepath );
		void* find_pattern( const module_t* mod, const char* pattern );
		void* get_proc_address( const module_t* mod, const char* func );
		bool dump_module_to_disk( const std::wstring& name );

		// unfinished
		bool map_image( const char* filepath );
	};

	template<typename memory_interface>
	inline void* process<memory_interface>::find_pattern( const module_t* mod, const char* pattern )
	{
		auto error = []( const char* msg ) -> void* { printf( msg ); return nullptr; };

		if ( !mod )
			return error( "[!] invalid module passed" );

		std::vector<std::byte> module_buffer( mod->size );

		if ( !try_read( mod->base, module_buffer.data(), mod->size ) )
			return error( "[!] failed to read module" );

		const auto addr = util::find_pattern( pattern, ( uintptr_t ) module_buffer.data(), mod->size );
		if ( addr )
			return ( void* ) ( addr - ( uintptr_t ) module_buffer.data() + ( uintptr_t ) mod->base );

		return nullptr;
	}

	template<typename memory_interface>
	inline void* process<memory_interface>::get_proc_address( const module_t* mod, const char* function_name )
	{
		auto error = []( const char* msg ) -> void* { printf( msg ); return nullptr; };

		if ( !mod )
			return error( "[!] invalid module passed" );

		// this will fail if the module base is different for our process.
		return GetProcAddress( ( HMODULE ) mod->base, function_name );
	}

	template<typename memory_interface>
	inline bool process<memory_interface>::try_read( void* address, void* buffer, size_t size, size_t max_attempts )
	{
		size_t attempts = 0;
		size_t num_reads = 1;

		while ( attempts < max_attempts && !read( address, buffer, size / num_reads ) )
		{
			num_reads *= 2;
			attempts++;
		}

		if ( attempts == max_attempts )
			return false;

		for ( size_t i = 1; i < num_reads; i++ )
		{
			read( PVOID( ( uintptr_t ) address + size / num_reads * i ),
				PVOID( ( uintptr_t ) buffer + size / num_reads * i ),
				size / num_reads );
		}

		return true;
	}

	template<typename memory_interface>
	inline module_t* process<memory_interface>::get_module( const std::wstring& name )
	{
		if ( auto it = m_modules.find( name ); it != m_modules.end() )
			return &it->second;

		const auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid );
		if ( snapshot == INVALID_HANDLE_VALUE )
			return nullptr;

		const scope_guard close_handle( [ snapshot ]() { CloseHandle( snapshot ); } );

		MODULEENTRY32 module_entry;
		module_entry.dwSize = sizeof( module_entry );

		if ( Module32First( snapshot, &module_entry ) )
		{
			do
			{
				if ( m_modules.find( module_entry.szModule ) == m_modules.end() )
					m_modules[ module_entry.szModule ] = { module_entry.modBaseAddr, module_entry.modBaseSize };

				if ( !_wcsicmp( name.c_str(), module_entry.szModule ) )
					return &m_modules[ module_entry.szModule ];

			} while ( Module32Next( snapshot, &module_entry ) );
		}

		return nullptr;
	}

	template<typename memory_interface>
	inline bool process<memory_interface>::load_image( const char* filepath )
	{
		auto error = []( const char* msg ) -> bool { printf( msg ); return false; };

		if ( !valid() )
			return error( "[!] invalid process\n" );

		const auto tid = util::get_window_tid( ( HANDLE ) m_pid );
		if ( !tid )
			return error( "[!] failed to get window tid\n" );

		printf( "[-] loading image\n" );

		if ( !std::filesystem::exists( filepath ) )
			return error( "\tfile not found\n" );

		const auto dll = LoadLibraryExA( filepath, NULL, DONT_RESOLVE_DLL_REFERENCES );
		if ( !dll )
			return error( "\tfailed to locally load image\n" );

		static auto dummy_function = ( HOOKPROC ) GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "GetTickCount64" );

		const auto hook_handle = SetWindowsHookEx( WH_GETMESSAGE, dummy_function, dll, tid );
		if ( !hook_handle )
			return error( "\tSetWindowsHookEx failed\n" );

		PostThreadMessage( tid, WM_NULL, NULL, NULL );

		return true;
	}

	template<typename memory_interface>
	bool process<memory_interface>::map_image( const char* filepath )
	{
		auto error = []( const char* msg ) -> bool { printf( msg ); return false; };

		// sanity check.

		if ( !valid() )
			return error( "[!] invalid process\n" );

		const auto tid = util::get_window_tid( ( HANDLE ) m_pid );
		if ( !tid )
			return error( "[!] failed to get window tid\n" );

		printf( "[-] reading file\n" );

		if ( !std::filesystem::exists( filepath ) )
			return error( "\tfile not found\n" );

		std::basic_ifstream<std::byte> filestream( filepath, std::ios::binary );
		if ( !filestream )
			return error( "\tfailed to open file stream\n" );

		std::vector<std::byte> disk_image = { std::istreambuf_iterator<std::byte>( filestream ), std::istreambuf_iterator<std::byte>() };

		filestream.close();

		const auto dos_header = ( IMAGE_DOS_HEADER* ) ( disk_image.data() );
		if ( !dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE )
			return error( "\tinvalid dos header\n" );

		const auto nt_headers = ( IMAGE_NT_HEADERS* ) ( ( uintptr_t ) dos_header + dos_header->e_lfanew );
		if ( !nt_headers || nt_headers->Signature != IMAGE_NT_SIGNATURE )
			return error( "\tinvalid nt headers\n" );

		// create buffer for image that will be loaded to memory.

		std::vector<std::byte> virtual_image( nt_headers->OptionalHeader.SizeOfImage );

		// copy headers and sections.

		memcpy( virtual_image.data(), disk_image.data(), nt_headers->OptionalHeader.SizeOfHeaders );

		const auto section_header = IMAGE_FIRST_SECTION( nt_headers );
		for ( WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++ )
		{
			memcpy( virtual_image.data() + section_header[ i ].VirtualAddress,
				disk_image.data() + section_header[ i ].PointerToRawData, section_header[ i ].SizeOfRawData );
		}

		printf( "[-] allocating memory to process\n" );

		auto base = alloc( ( LPVOID ) nt_headers->OptionalHeader.ImageBase, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		if ( !base )
		{
			base = alloc( nullptr, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if ( !base )
				return error( "\tfailed to allocate memory\n" );
		}

		printf( "[-] applying base relocations\n" );

		const auto delta = ( uintptr_t ) base - nt_headers->OptionalHeader.ImageBase;

		if ( nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size && delta )
		{
			auto relocation_block = ( IMAGE_BASE_RELOCATION* ) ( virtual_image.data() + nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );

			while ( relocation_block->VirtualAddress )
			{
				const size_t block_entries = ( relocation_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );

				for ( size_t i = 0; i < block_entries; i++ )
				{
					const auto block_entry = ( ( WORD* ) ( relocation_block + 1 ) )[ i ];

					const uint8_t type = block_entry >> 12;
					const uint16_t offset = block_entry & 0xFFF;

					if ( type == IMAGE_REL_BASED_HIGHLOW )
					{
						uint32_t* absolute_address = ( uint32_t* ) ( virtual_image.data() + relocation_block->VirtualAddress + offset );
						*absolute_address += delta;
					}
					else if ( type == IMAGE_REL_BASED_DIR64 )
					{
						uint64_t* absolute_address = ( uint64_t* ) ( virtual_image.data() + relocation_block->VirtualAddress + offset );
						*absolute_address += delta;
					}
				}

				relocation_block = ( IMAGE_BASE_RELOCATION* ) ( ( uintptr_t ) relocation_block + relocation_block->SizeOfBlock );
			}
		}

		printf( "[-] resolving imports\n" );

		if ( nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
		{
			auto descriptor_table_entry = ( IMAGE_IMPORT_DESCRIPTOR* ) ( virtual_image.data() + nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
			while ( descriptor_table_entry->OriginalFirstThunk )
			{
				auto* lookup_table_entry = ( IMAGE_THUNK_DATA* ) ( virtual_image.data() + descriptor_table_entry->OriginalFirstThunk );
				auto* address_table_entry = ( IMAGE_THUNK_DATA* ) ( virtual_image.data() + descriptor_table_entry->FirstThunk );

				std::string module_name = ( ( LPCSTR ) ( virtual_image.data() + descriptor_table_entry->Name ) );
				if ( !strncmp( "api-ms", module_name.c_str(), 6 ) )
					module_name = get_dll_name_from_api_set_map( module_name );

				const std::wstring wide_name = { module_name.begin(), module_name.end() };

				const auto import_library = LoadLibraryExA( module_name.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES );
				if ( !import_library )
					return error( std::format( "\t{} not found\n", module_name ).c_str() );

				if ( !get_module( wide_name ) )
				{
					printf( "\tloading % into process\n", module_name.c_str() );

					static auto kernel32 = GetModuleHandle( L"kernel32.dll" );
					static auto func = ( HOOKPROC ) GetProcAddress( kernel32, "GetTickCount64" );

					const auto hook_handle = SetWindowsHookEx( WH_GETMESSAGE, func, import_library, tid );
					if ( !hook_handle )
						return error( "\tsetwindowshookex failed\n" );

					PostThreadMessage( tid, WM_NULL, NULL, NULL );
				}

				while ( lookup_table_entry->u1.AddressOfData )
				{
					if ( lookup_table_entry->u1.AddressOfData & IMAGE_ORDINAL_FLAG )
					{
						// import by ordinal.

						const auto import_address = GetProcAddress( import_library, ( LPCSTR ) ( lookup_table_entry->u1.AddressOfData & 0xFFFF ) );
						if ( !import_address )
							return error( "\tordinal not found\n" );

						address_table_entry->u1.AddressOfData = ( uintptr_t ) import_address;
					}
					else
					{
						// import by name.

						const auto import_address = GetProcAddress( import_library, ( ( IMAGE_IMPORT_BY_NAME* ) ( virtual_image.data() + lookup_table_entry->u1.AddressOfData ) )->Name );
						if ( !import_address )
							return error( std::format( "\timport {} not found\n", ( ( IMAGE_IMPORT_BY_NAME* ) ( virtual_image.data() + lookup_table_entry->u1.AddressOfData ) )->Name ).c_str() );

						address_table_entry->u1.AddressOfData = ( uintptr_t ) import_address;
					}

					lookup_table_entry++;
					address_table_entry++;
				}

				descriptor_table_entry++;
			}
		}

		printf( "[-] writing image to process\n" );

		if ( !write( base, virtual_image.data(), nt_headers->OptionalHeader.SizeOfImage ) )
			return error( "\tfailed to write image\n" );

		// todo
		// call entry point...

		printf( "[+] %s injected\n", filepath );

		return false;
	}

	template<typename memory_interface>
	bool process<memory_interface>::dump_module_to_disk( const std::wstring& name )
	{
		auto error = []( const char* msg ) -> bool { printf( msg ); return false; };

		const auto narrow_name = std::string( name.begin(), name.end() );

		const auto mod = get_module( name );
		if ( !mod )
			return error( std::format( "[!] could not find {}\n", narrow_name ).c_str() );

		std::vector<std::byte> module_buffer( mod->size );

		if ( !try_read( mod->base, module_buffer.data(), mod->size ) )
			return error( std::format( "[!] failed reading {}\n", narrow_name ).c_str() );

		std::stringstream file_name;
		file_name << narrow_name.c_str() << ".bin";

		std::ofstream dump_file( file_name.str(), std::ios::binary );
		if ( !dump_file )
			return error( "[!] failed to open output stream" );

		dump_file.write( ( const char* ) module_buffer.data(), mod->size );

		dump_file.close();

		return true;
	}

}