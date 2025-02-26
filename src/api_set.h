#pragma once

#include <wtypes.h>
#include <string>
#include <winternl.h>

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;
 
typedef struct _API_SET_HASH_ENTRY {
	ULONG Hash;
	ULONG Index;
} API_SET_HASH_ENTRY, * PAPI_SET_HASH_ENTRY;
 
typedef struct _API_SET_NAMESPACE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, * PAPI_SET_NAMESPACE_ENTRY;
 
typedef struct _API_SET_VALUE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, * PAPI_SET_VALUE_ENTRY;

//https://github.com/zodiacon/WindowsInternals/blob/master/APISetMap/APISetMap.cpp
inline std::string get_dll_name_from_api_set_map(const std::string& api_set)
{
	const std::wstring wapi_set( api_set.begin(), api_set.end() );

	PEB* peb = reinterpret_cast< PEB* >( NtCurrentTeb()->ProcessEnvironmentBlock );
	API_SET_NAMESPACE* apiSetMap = static_cast< API_SET_NAMESPACE* >( peb->Reserved9[ 0 ] );
	ULONG_PTR apiSetMapAsNumber = reinterpret_cast< ULONG_PTR >( apiSetMap );
	API_SET_NAMESPACE_ENTRY* nsEntry = reinterpret_cast< API_SET_NAMESPACE_ENTRY* >( ( apiSetMap->EntryOffset + apiSetMapAsNumber ) );

    for ( ULONG i = 0; i < apiSetMap->Count; i++ )
	{
		UNICODE_STRING nameString, valueString;
		nameString.MaximumLength = static_cast< USHORT >( nsEntry->NameLength );
		nameString.Length = static_cast< USHORT >( nsEntry->NameLength );
        nameString.Buffer = reinterpret_cast<PWCHAR>(apiSetMapAsNumber + nsEntry->NameOffset);
        
		std::wstring name( nameString.Buffer, nameString.Length / sizeof( WCHAR ) );
		name += L".dll";

		if ( !_wcsicmp( wapi_set.c_str(), name.c_str() ) )
		{
			API_SET_VALUE_ENTRY* valueEntry = reinterpret_cast< API_SET_VALUE_ENTRY* >( apiSetMapAsNumber + nsEntry->ValueOffset );
			if ( !nsEntry->ValueCount )
				return "";

			valueString.Buffer = reinterpret_cast< PWCHAR >( apiSetMapAsNumber + valueEntry->ValueOffset );
			valueString.MaximumLength = static_cast< USHORT >( valueEntry->ValueLength );
			valueString.Length = static_cast< USHORT >( valueEntry->ValueLength );

			std::wstring value( valueString.Buffer, valueString.Length / sizeof( WCHAR ) );
			return std::string( value.begin(), value.end() );
		}

        nsEntry++;
    }

    return "";
}