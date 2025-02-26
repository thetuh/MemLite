#pragma once

#include <wtypes.h>
#include <utility>
#include <TlHelp32.h>

#include "scope_guard.h"

namespace util
{
    inline uintptr_t find_pattern( const char* pattern, const std::uintptr_t base, const size_t size ) noexcept
    {
        if ( !base || !size )
            return 0;

        auto pattern_to_bytes = []( const char* patt, std::vector<int>& bytes ) noexcept -> bool
        {
            bytes.clear();
            auto start = const_cast< char* >( patt );
            auto end = const_cast< char* >( patt ) + std::strlen( patt );

            for ( auto current = start; current < end; ++current )
            {
                if ( *current == '?' )
                {
                    ++current;

                    if ( *current == '?' )
                        ++current;

                    bytes.push_back( -1 );
                }
                else
                    bytes.push_back( strtoul( current, &current, 16 ) );
            }

            return bytes.size();
        };

        std::vector<int> bytes;
        pattern_to_bytes( pattern, bytes );
        auto s = bytes.size();
        if ( size < s )
            return 0;

        auto d = bytes.data();
        auto scan_bytes = reinterpret_cast< std::uint8_t* >( base );

        for ( auto i = 0ul; i < size - s; ++i )
        {
            bool found = true;

            for ( auto j = 0ul; j < s; ++j )
            {
                if ( scan_bytes[ i + j ] != d[ j ] && d[ j ] != -1 )
                {
                    found = false;
                    break;
                }
            }

            if ( found )
                return reinterpret_cast< uintptr_t >( &scan_bytes[ i ] );
        }

        return 0;
    }

	inline DWORD get_proc_id( const wchar_t* proc_name )
	{
		const HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if ( snapshot == INVALID_HANDLE_VALUE )
			return 0;

		const scope_guard close_handle([snapshot](){ CloseHandle(snapshot); });

		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof( PROCESSENTRY32 );

		if ( Process32First( snapshot, &process_entry ) )
		{
			do
			{
				if ( !_wcsicmp( proc_name, process_entry.szExeFile ) )
					return process_entry.th32ProcessID;

			} while ( Process32Next( snapshot, &process_entry ) );
		}

		return 0;
	}

	inline DWORD get_window_tid(HANDLE pid)
	{
		std::pair<DWORD, DWORD> params = { 0, static_cast<DWORD>(reinterpret_cast<uintptr_t>(pid)) };
		BOOL bresult = EnumWindows([](HWND hwnd, LPARAM lparam) -> BOOL
		{
			auto pparams = reinterpret_cast<std::pair<DWORD, DWORD>*>(lparam);
			DWORD processid = 0;
			if (const auto tid = GetWindowThreadProcessId(hwnd, &processid); tid && processid == pparams->second)
			{
				SetLastError(static_cast<uint32_t>(-1));
				pparams->first = tid;
				return FALSE;
			}
			return TRUE;
		}, reinterpret_cast<LPARAM>(&params));
    
		if (!bresult && GetLastError() == static_cast<uint32_t>(-1) && params.first != 0) 
			return params.first;

		return 0;
	}
}