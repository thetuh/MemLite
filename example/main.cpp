#include "../src/process.h"

int main( int argc, char* argv[] )
{
	auto error = []( const char* msg ) -> int { printf( msg ); system( "pause" ); return 1; };

	if ( argc != 3 )
		return error( std::format( "[!] usage: {} <process_name> <dll_path>\n", argv[ 0 ] ).c_str() );

	const std::wstring process_name = { argv[ 1 ], &argv[ 1 ][ strlen( argv[ 1 ] ) ] };

	memlite::process proc( memlite::util::get_proc_id( process_name.c_str() ) );
	if ( !proc.valid() )
		return error( "[!] failed to attach to process\n" );

	const auto mod = proc.get_module( L"kernel32.dll" );
	if ( !mod )
		return error( "[!] failed to find module\n" );

	printf( "[+] kernel32.dll: 0x%llx\n", mod->base );

	const auto func = proc.get_proc_address( mod, "LoadLibraryA" );
	if ( !func )
		return error( "[!] failed to find function export\n" );

	printf( "[+] export (LoadLibraryA): 0x%llx\n", func );

	// "This program cannot be run in DOS mode"
	constexpr auto pattern = "54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65";

	const auto pattern_address = proc.find_pattern( mod, pattern );
	if ( !pattern_address )
		return error( "[!] failed to find pattern\n" );

	printf( "[+] pattern location: 0x%llx\n", pattern_address );

	if ( proc.load_image( argv[ 2 ] ) )
		printf( "[+] injected %s\n", argv[ 2 ] );

	if ( proc.dump_module_to_disk( process_name ) )
		printf( "[+] dumped %ls\n", process_name.c_str() );

	system( "pause" );
}