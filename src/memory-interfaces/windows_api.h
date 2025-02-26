#pragma once

namespace memlite {

	template <typename memory_interface>
	class process;

	namespace interfaces {

		class windows_api
		{
		private:
			friend class process<windows_api>;

			HANDLE m_handle = nullptr;
			DWORD m_pid = 0;

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
		};

	}

}
