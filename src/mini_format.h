#pragma once

#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <type_traits>

namespace memlite::mfm {

	template<typename T>
	inline void format_arg( std::ostringstream& oss, char spec, const T& value )
	{
		if ( spec == 'x' )
		{
			oss << std::hex << value;
		}
		else if ( spec == 'p' )
		{
			if constexpr ( std::is_pointer_v<T> )
				oss << "0x" << std::hex << reinterpret_cast< uintptr_t >( value );
			else
				oss << value;
		}
		else
		{
			oss << value;
		}
	}

	template<typename... Args>
	inline std::string format( const std::string& fmt, const Args&... args )
	{
		std::ostringstream oss;
		size_t pos = 0;
		size_t arg_idx = 0;
		const auto total_args = sizeof...( args );
		auto unpack = [ & ]( const auto&... unpacked )
			{
				const auto arg_arr = { ( &unpacked )... };
				for ( const auto* arg_ptr : arg_arr )
				{
					size_t start = fmt.find( '%', pos );
					if ( start == std::string::npos || arg_idx >= total_args )
						break;

					// write the preceding text.
					oss.write( fmt.data() + pos, start - pos );

					// handle format specifier.
					char spec = ( start + 1 < fmt.size() ) ? fmt[ start + 1 ] : '\0';
					if ( spec )
					{
						format_arg( oss, spec, *arg_ptr );
						pos = start + 2;
					}
					else
					{
						oss.put( '%' );
						pos = start + 1;
					}

					++arg_idx;
				}
			};

		unpack( args... );

		// append the remaining part of the format string.
		oss.write( fmt.data() + pos, fmt.size() - pos );
		return oss.str();
	}

}