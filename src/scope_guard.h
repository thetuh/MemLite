#pragma once

#include <functional>

namespace memlite {

	template <typename fn_callback, typename... fn_args>
	class scope_guard
	{
	public:
		scope_guard( const fn_callback& callback, const fn_args& ...args ) : callback{ callback }, args{ args... }, active( true ) { }
		~scope_guard() { execute(); }

	public:
		void execute() { if ( active ) { invoke_callable( std::make_index_sequence < std::tuple_size_v<std::tuple<fn_args...>>>() ); active = false; } }
		void cancel() { active = false; }

	private:
		template <size_t... Is>
		void invoke_callable( std::index_sequence<Is...> ) { std::invoke( callback, std::get<Is>( args )... ); }

	private:
		const fn_callback callback;
		const std::tuple< fn_args... > args;
		bool active;
	};

}