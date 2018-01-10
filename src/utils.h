/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2017 Jernej Turnsek
 * Copyright (C) 2017 Iwan Timmer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef FALSE
# define FALSE false
#endif /* FALSE */
#ifndef TRUE
# define TRUE  true
#endif /* TRUE */

/**
 * Number of bits in a byte
 */
#define BITS_PER_BYTE 8

/**
 * Default length for various auxiliary text buffers
 */
#define BUF_LEN 512

/**
 * Build assertion macro for integer expressions, evaluates to 0
 */
#define BUILD_ASSERT(x) (sizeof(char[(x) ? 0 : -1]))

/**
 * Build time check to assert a is an array, evaluates to 0
 *
 * The address of an array element has a pointer type, which is not compatible
 * to the array type.
 */
#define BUILD_ASSERT_ARRAY(a) \
		BUILD_ASSERT(!__builtin_types_compatible_p(typeof(a), typeof(&(a)[0])))

/**
 * Debug macro to follow control flow
 */
#define POS printf("%s, line %d\n", __FILE__, __LINE__)

/**
 * This macro allows counting the number of arguments passed to a macro.
 * Combined with the VA_ARGS_DISPATCH() macro this can be used to implement
 * macro overloading based on the number of arguments.
 * 0 to 10 arguments are currently supported.
 */
#define VA_ARGS_NUM(...) _VA_ARGS_NUM(0,##__VA_ARGS__,10,9,8,7,6,5,4,3,2,1,0)
#define _VA_ARGS_NUM(_0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,NUM,...) NUM

/**
 * This macro can be used to dispatch a macro call based on the number of given
 * arguments, for instance:
 *
 * @code
 * #define MY_MACRO(...) VA_ARGS_DISPATCH(MY_MACRO, __VA_ARGS__)(__VA_ARGS__)
 * #define MY_MACRO1(arg) one_arg(arg)
 * #define MY_MACRO2(arg1,arg2) two_args(arg1,arg2)
 * @endcode
 *
 * MY_MACRO() can now be called with either one or two arguments, which will
 * resolve to one_arg(arg) or two_args(arg1,arg2), respectively.
 */
#define VA_ARGS_DISPATCH(func, ...) _VA_ARGS_DISPATCH(func, VA_ARGS_NUM(__VA_ARGS__))
#define _VA_ARGS_DISPATCH(func, num) __VA_ARGS_DISPATCH(func, num)
#define __VA_ARGS_DISPATCH(func, num) func ## num

/**
 * Assign variadic arguments to the given variables.
 *
 * @note The order and types of the variables are significant and must match the
 * variadic arguments passed to the function that calls this macro exactly.
 *
 * @param last		the last argument before ... in the function that calls this
 * @param ...		variable names
 */
#define VA_ARGS_GET(last, ...) ({ \
	va_list _va_args_get_ap; \
	va_start(_va_args_get_ap, last); \
	_VA_ARGS_GET_ASGN(__VA_ARGS__) \
	va_end(_va_args_get_ap); \
})

/**
 * Assign variadic arguments from a va_list to the given variables.
 *
 * @note The order and types of the variables are significant and must match the
 * variadic arguments passed to the function that calls this macro exactly.
 *
 * @param list		the va_list variable in the function that calls this
 * @param ...		variable names
 */
#define VA_ARGS_VGET(list, ...) ({ \
	va_list _va_args_get_ap; \
	va_copy(_va_args_get_ap, list); \
	_VA_ARGS_GET_ASGN(__VA_ARGS__) \
	va_end(_va_args_get_ap); \
})

#define _VA_ARGS_GET_ASGN(...) VA_ARGS_DISPATCH(_VA_ARGS_GET_ASGN, __VA_ARGS__)(__VA_ARGS__)
#define _VA_ARGS_GET_ASGN1(v1) __VA_ARGS_GET_ASGN(v1)
#define _VA_ARGS_GET_ASGN2(v1,v2) __VA_ARGS_GET_ASGN(v1) __VA_ARGS_GET_ASGN(v2)
#define _VA_ARGS_GET_ASGN3(v1,v2,v3) __VA_ARGS_GET_ASGN(v1) __VA_ARGS_GET_ASGN(v2) \
	__VA_ARGS_GET_ASGN(v3)
#define _VA_ARGS_GET_ASGN4(v1,v2,v3,v4) __VA_ARGS_GET_ASGN(v1) __VA_ARGS_GET_ASGN(v2) \
	__VA_ARGS_GET_ASGN(v3) __VA_ARGS_GET_ASGN(v4)
#define _VA_ARGS_GET_ASGN5(v1,v2,v3,v4,v5) __VA_ARGS_GET_ASGN(v1) __VA_ARGS_GET_ASGN(v2) \
	__VA_ARGS_GET_ASGN(v3) __VA_ARGS_GET_ASGN(v4) __VA_ARGS_GET_ASGN(v5)
#define __VA_ARGS_GET_ASGN(v) v = va_arg(_va_args_get_ap, typeof(v));


/**
 * Call destructor of an object, if object != NULL
 */
#define DESTROY_IF(obj) if (obj) (obj)->destroy(obj)

/**
 * Call offset destructor of an object, if object != NULL
 */
#define DESTROY_OFFSET_IF(obj, offset) if (obj) obj->destroy_offset(obj, offset);

/**
 * Call function destructor of an object, if object != NULL
 */
#define DESTROY_FUNCTION_IF(obj, fn) if (obj) obj->destroy_function(obj, fn);

/**
 * Object allocation/initialization macro, using designated initializer.
 */
#define INIT(this, ...) { (this) = malloc(sizeof(*(this))); \
						   *(this) = (typeof(*(this))){ __VA_ARGS__ }; }

/**
 * Aligning version of INIT().
 *
 * The returned pointer must be freed using free_align(), not free().
 *
 * @param this		object to allocate/initialize
 * @param align		alignment for allocation, in bytes
 * @param ...		initializer
 */
#define INIT_ALIGN(this, align, ...) { \
						(this) = malloc_align(sizeof(*(this)), align); \
						*(this) = (typeof(*(this))){ __VA_ARGS__ }; }

/**
 * Object allocation/initialization macro, with extra allocated bytes at tail.
 *
 * The extra space gets zero-initialized.
 *
 * @param this		pointer to object to allocate memory for
 * @param extra		number of bytes to allocate at end of this
 * @param ...		initializer
 */
#define INIT_EXTRA(this, extra, ...) { \
						typeof(extra) _extra = (extra); \
						(this) = malloc(sizeof(*(this)) + _extra); \
						*(this) = (typeof(*(this))){ __VA_ARGS__ }; \
						memset((this) + 1, 0, _extra); }

/**
 * Aligning version of INIT_EXTRA().
 *
 * The returned pointer must be freed using free_align(), not free().
 *
 * @param this		object to allocate/initialize
 * @param extra		number of bytes to allocate at end of this
 * @param align		alignment for allocation, in bytes
 * @param ...		initializer
 */
#define INIT_EXTRA_ALIGN(this, extra, align, ...) { \
						typeof(extra) _extra = (extra); \
						(this) = malloc_align(sizeof(*(this)) + _extra, align); \
						*(this) = (typeof(*(this))){ __VA_ARGS__ }; \
						memset((this) + 1, 0, _extra); }

/**
 * Method declaration/definition macro, providing private and public interface.
 *
 * Defines a method name with this as first parameter and a return value ret,
 * and an alias for this method with a _ prefix, having the this argument
 * safely casted to the public interface iface.
 * _name is provided a function pointer, but will get optimized out by GCC.
 */
#define METHOD(iface, name, ret, this, ...) \
	static ret name(union {iface *_public; this;} \
	__attribute__((transparent_union)), ##__VA_ARGS__); \
	static typeof(name) *_##name = (typeof(name)*)name; \
	static ret name(this, ##__VA_ARGS__)

/**
 * Same as METHOD(), but is defined for two public interfaces.
 */
#define METHOD2(iface1, iface2, name, ret, this, ...) \
	static ret name(union {iface1 *_public1; iface2 *_public2; this;} \
	__attribute__((transparent_union)), ##__VA_ARGS__); \
	static typeof(name) *_##name = (typeof(name)*)name; \
	static ret name(this, ##__VA_ARGS__)

/**
 * Callback declaration/definition macro, allowing casted first parameter.
 *
 * This is very similar to METHOD, but instead of casting the first parameter
 * to a public interface, it uses a void*. This allows type safe definition
 * of a callback function, while using the real type for the first parameter.
 */
#define CALLBACK(name, ret, param1, ...) \
	static ret _cb_##name(union {void *_generic; param1;} \
	__attribute__((transparent_union)), ##__VA_ARGS__); \
	static typeof(_cb_##name) *name = (typeof(_cb_##name)*)_cb_##name; \
	static ret _cb_##name(param1, ##__VA_ARGS__)


void strncpy_pad(char *dest, const char *src, size_t n);
void retmem(void* dest, size_t* size, const void* src, size_t n);
void* read_file(const char* filename, size_t* length);
