#pragma once

#include <unordered_map>
#include <wtypes.h>
#include <string>

#include "scope_guard.h"

struct module_t
{
    void* base;
    size_t size;
};

template <typename memory_interface> class process;
namespace memory_interface
{
    class windows_api
    {
    private:
        HANDLE m_handle = nullptr;
        DWORD m_pid = 0;
        std::unordered_map<std::wstring, module_t> m_modules = {};

        bool attach( DWORD pid )
        {
            if ( m_handle )
                detach();

            m_pid = pid;
            m_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, m_pid );
            return m_handle;
        }

        bool detach()
        {
            if ( m_handle && CloseHandle( m_handle ) )
            {
                m_handle = nullptr;
                return true;
            }

            return false;
        }

        bool read( void* address, void* buffer, size_t size )
        {
            if ( !m_handle )
                return false;

            return ReadProcessMemory( m_handle, address, buffer, size, nullptr );
        }

        bool write( void* address, void* buffer, size_t size )
        {
            if ( !m_handle )
                return false;

            return WriteProcessMemory( m_handle, address, buffer, size, nullptr );
        }

        void* alloc( void* address, size_t size, DWORD allocation_type, DWORD protect )
        {
            if ( !m_handle )
                return nullptr;

            return VirtualAllocEx( m_handle, address, size, allocation_type, protect );
        }

    public:
        HANDLE get_handle() const { return m_handle; }
        module_t* get_module( const std::wstring& name );

        friend class process<windows_api>;
    };

    class driver_api
    {

    };
}

module_t* memory_interface::windows_api::get_module( const std::wstring& name )
{
    if ( auto it = m_modules.find( name ); it != m_modules.end() )
        return &it->second;

	const auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid );
    if ( snapshot == INVALID_HANDLE_VALUE )
        return nullptr;

    const scope_guard close_handle([snapshot](){ CloseHandle(snapshot); });

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