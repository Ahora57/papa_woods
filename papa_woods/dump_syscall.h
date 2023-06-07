#ifndef SYSCALL_DUMPER_ENABLE
#define SYSCALL_DUMPER_ENABLE 1

#include "nt_api_def.h"
#include <cstdint>
#include "lazy_importer.hpp"
#include "distorm.h"
#include "mnemonics.h" 

namespace detail
{
	template <typename Type, Type OffsetBasis, Type Prime>
	struct size_dependant_data
	{
		using type = Type;
		constexpr static auto k_offset_basis = OffsetBasis;
		constexpr static auto k_prime = Prime;
	};

	template <size_t Bits>
	struct size_selector;

	template <>
	struct size_selector<32>
	{
		using type = size_dependant_data<std::uint32_t, 0x811c9dc5ul - __TIME__[7] - __TIME__[4], 16777619ul- __TIME__[7] - __TIME__[4] >;
	};

	template <>
	struct size_selector<64>
	{
		using type = size_dependant_data<std::uint64_t, 0xcbf29ce484222325ull -__TIME__[7] - __TIME__[4], 1099511628211ull - __TIME__[7] - __TIME__[4]>;
	};

	// Implements FNV-1a hash algorithm
	template <std::size_t Size>
	class fnv_hash
	{
	private:
		using data_t = typename size_selector<Size>::type;

	public:
		using hash = typename data_t::type;

	private:
		constexpr static auto k_offset_basis = data_t::k_offset_basis;
		constexpr static auto k_prime = data_t::k_prime;

	public:
		template <std::size_t N>
		static __forceinline constexpr auto hash_constexpr(const char(&str)[N], const std::size_t size = N) -> hash
		{
			return static_cast<hash>(1ull * (size == 1
				? (k_offset_basis ^ str[0])
				: (hash_constexpr(str, size - 1) ^ str[size - 1])) * k_prime);
		}

		static auto __forceinline hash_runtime(const char* str) -> hash
		{
			auto result = k_offset_basis;
			do
			{
				result ^= *str++;
				result *= k_prime;
			} while (*(str - 1) != '\0');

			return result;
		}

		template <std::size_t N>
		static __forceinline constexpr auto hash_constexpr(const wchar_t(&str)[N], const std::size_t size = N) -> hash
		{
			return static_cast<hash>(1ull * (size == 1
				? (k_offset_basis ^ str[0])
				: (hash_constexpr(str, size - 1) ^ str[size - 1])) * k_prime);
		}

		static auto __forceinline hash_runtime(const wchar_t* str) -> hash
		{
			auto result = k_offset_basis;
			do
			{
				result ^= *str++;
				result *= k_prime;
			} while (*(str - 1) != '\0');

			return result;
		}
	};
}

using fnv = ::detail::fnv_hash<sizeof(PVOID) * 8>;

#define FNV(str) (std::integral_constant<fnv::hash, fnv::hash_constexpr(str)>::value)
 
namespace dump_syscall_util
{

	 
	namespace crt_wrapper
	{
		INLINE auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		}

		INLINE auto free(PVOID ptr) -> VOID
		{
			if (nullptr != ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}

		INLINE auto memset(PVOID dest, CHAR c, UINT len) -> PVOID
		{
			UINT i;
			UINT fill;
			UINT chunks = len / sizeof(fill);
			CHAR* char_dest = (CHAR*)dest;
			unsigned int* uint_dest = (UINT*)dest;
			fill = (c << 24) + (c << 16) + (c << 8) + c;

			for (i = len; i > chunks * sizeof(fill); i--) {
				char_dest[i - 1] = c;
			}

			for (i = chunks; i > NULL; i--) {
				uint_dest[i - 1] = fill;
			}

			return dest;
		}

		INLINE auto str_cat_w(WCHAR* dest, CONST WCHAR* src) -> WCHAR*
		{
			if ((dest == NULL) || (src == NULL))
				return dest;

			while (*dest != NULL)
				dest++;

			while (*src != NULL)
			{
				*dest = *src;
				dest++;
				src++;
			}

			*dest = NULL;
			return dest;
		}

		INLINE auto wstrlen(CONST WCHAR* s) -> INT
		{
			INT cnt = NULL;
			if (!s)
				return NULL;
			for (; *s != NULL; ++s)
				++cnt;
			return cnt * sizeof(WCHAR);
		}

		INLINE auto  wtolower(INT c) -> INT
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			return c;
		}


		INLINE auto  wstricmp(CONST WCHAR* cs, CONST WCHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == NULL && *ct == NULL) return NULL;
					if (*cs == NULL || *ct == NULL) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}

		INLINE auto init_unicode_str(CONST WCHAR* string_to_init) -> UNICODE_STRING
		{

			UNICODE_STRING string_init;
			if (string_to_init)
			{
				string_init.Length = wstrlen(string_to_init);
				string_init.MaximumLength = string_init.Length + sizeof(WCHAR);
				string_init.Buffer = (WCHAR*)string_to_init;
			}
			return string_init;
		}

		INLINE auto strcmp(CONST CHAR* cs, CONST CHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (*cs == *ct)
				{
					if (*cs == NULL && *ct == NULL) return NULL;
					if (*cs == NULL || *ct == NULL) break;
					cs++;
					ct++;
				}
				return *cs - *ct;
			}
			return -1;
		}

		INLINE auto  get_module_address(uint64_t hash_module) -> PVOID
		{
			LDR_DATA_TABLE_ENTRY* modEntry = nullptr;

#ifdef _WIN64
			PEB* peb = (PEB*)__readgsqword(0x60);

#else
			PEB* peb = (PEB*)__readfsdword(0x30);
#endif

			LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

			LIST_ENTRY curr = head;

			for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
			{
				LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

				if (mod->BaseDllName.Buffer)
				{
					if (!hash_module)
					{
						modEntry = mod;
						break;
					}
					if (hash_module == fnv::hash_runtime(mod->BaseDllName.Buffer))
					{
						modEntry = mod;
						break;
					}
				}
			}
			if (modEntry)
				return reinterpret_cast<PVOID>(modEntry->DllBase);
			return NULL;
		}

		INLINE auto get_proc_address(PVOID base_module, uint64_t hash_str) -> PVOID
		{
			DWORD64 base = (DWORD64)base_module;
			if (!base)
				return NULL;

			auto image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
			if (image_dos->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			auto image_nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image_dos->e_lfanew);
			if (image_nt_head->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!pExport)
				return NULL; 

			//reinterpret_cast break this
			auto names = (PDWORD)(base + pExport->AddressOfNames);
			auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
			auto functions = (PDWORD)(base + pExport->AddressOfFunctions);

			if (!names || !ordinals || !functions)
				return NULL; 

			for (uint32_t i = NULL; i < pExport->NumberOfFunctions; ++i)
			{
				auto name = reinterpret_cast<CHAR*>(base + names[i]);
				if (hash_str == fnv::hash_runtime(name))
					return  reinterpret_cast<PVOID>(base + functions[ordinals[i]]);
			}
			return NULL;
		}
	
		//SharrOD bypass if map file
		INLINE auto get_address_by_rva(CONST WCHAR* name_module, PVOID mapped_base,uint64_t hash_str) -> PVOID
		{
			bool is_pe_machine_correct = FALSE;
			uint64_t rva_offset = NULL;
			uint64_t address_api = NULL; 

			DWORD64 base = (DWORD64)get_module_address(fnv::hash_runtime(name_module));
			if (!base || !mapped_base)
				return NULL;

			auto image_dos_map = reinterpret_cast<PIMAGE_DOS_HEADER>(mapped_base);
			if (image_dos_map->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			auto image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
			if (image_dos->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;
			  
			auto image_nt_head_map = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint64_t>(mapped_base) + image_dos_map->e_lfanew);
			if (image_nt_head_map->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			auto image_nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image_dos->e_lfanew);
			if (image_nt_head->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!pExport)
				return NULL;
			 
			auto names = (PDWORD)(base + pExport->AddressOfNames);
			auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
			auto functions = (PDWORD)(base + pExport->AddressOfFunctions);

			if (!names || !ordinals || !functions)
				return NULL; 

			for (uint32_t i = NULL; i < pExport->NumberOfFunctions; ++i)
			{
				auto name = reinterpret_cast<CHAR*>(base + names[i]);
				if (hash_str == fnv::hash_runtime(name))
					address_api = reinterpret_cast<uint64_t>(base + functions[ordinals[i]]);
			}

			is_pe_machine_correct = image_nt_head->FileHeader.Machine == image_nt_head_map->FileHeader.Machine;
 			if (is_pe_machine_correct && address_api && address_api > base && base + image_nt_head->OptionalHeader.SizeOfImage > address_api)
			{
				rva_offset = address_api - base;
				return  reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(mapped_base) + rva_offset);
			}
			return NULL;
		}

}

	namespace get_proc_info
	{

		ALLOCATE_TEXT  uint8_t get_process_info[] =
		{
			0x66, 0x8C, 0xC8, //mov ax, cs
			0xC3 //ret
		};

		INLINE  auto get_process_platform() -> INT
		{
			INT proc = NULL;
			proc = reinterpret_cast<uint8_t(__cdecl*)()>(get_proc_info::get_process_info)();
			if (proc == CS_64)
				return PROCESS_64;
			else if (proc == CS_WOW)
				return PROCESS_WOW64;
			else if (proc == CS_32)
				return PROCESS_32;
			else
				PROCESS_UNK;
		}


	}


	class syscall_help_map
	{
	private:

		INT process_platrorm = NULL;

		//Map file
		PVOID nt_open_secthion = NULL;
		PVOID nt_map_view_of_secthion = NULL;
		PVOID nt_close = NULL;
		PVOID nt_unmap_view_of_secthion = NULL;


		INLINE auto init_struct() -> bool
		{
			if ( process_platrorm && nt_open_secthion && nt_map_view_of_secthion && nt_close && nt_unmap_view_of_secthion)
				return TRUE;
			process_platrorm = get_proc_info::get_process_platform();
			nt_open_secthion = LI_FN(NtOpenSection).nt_cached();
			nt_map_view_of_secthion = LI_FN(NtMapViewOfSection).nt_cached();
			nt_close = LI_FN(NtClose).nt_cached();
			nt_unmap_view_of_secthion = LI_FN(NtUnmapViewOfSection).nt_cached();
			 

			return nt_open_secthion && nt_map_view_of_secthion && nt_close && nt_unmap_view_of_secthion;
		}

	public:
		 
		INLINE auto map_get_syscall(CONST WCHAR* name_module, uint64_t hahs_str) -> INT
		{
			INT syscall_number = NULL;
			SIZE_T viewSize = NULL;
			HANDLE secthion_handle = NULL;
			PVOID functhion_address = NULL;
			PVOID mapped_module = NULL;
			UNICODE_STRING secthion_name = { NULL };
			OBJECT_ATTRIBUTES obj_attribut = { NULL };
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			WCHAR buffer[MAX_PATH];

			 
			bool is_read_success = FALSE;
			uint32_t size_file = NULL;
			DWORD num_read = NULL;
			PVOID allocate_file = NULL;
			HANDLE file = NULL;
			  

			//Disassembly
			UINT count_decode = NULL;
			_CodeInfo ci = { NULL };
			_DInst decode_instr[100] = { NULL };

			if (!init_struct())
				return NULL;
			crt_wrapper:memset(buffer, NULL, MAX_PATH);
			
#ifdef _WIN64
			crt_wrapper::str_cat_w(buffer, L"\\KnownDlls\\");
#else 
			if (process_platrorm == PROCESS_WOW64)
					crt_wrapper::str_cat_w(buffer, L"\\KnownDlls32\\");
			else
				crt_wrapper::str_cat_w(buffer, L"\\KnownDlls\\");
#endif   
			crt_wrapper::str_cat_w(buffer, name_module);

			secthion_name = crt_wrapper::init_unicode_str(buffer);

			InitializeObjectAttributes(&obj_attribut, &secthion_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
			
			nt_status = reinterpret_cast<decltype(&NtOpenSection)>(nt_open_secthion)(&secthion_handle, SECTION_MAP_READ, &obj_attribut);

			if (!NT_SUCCESS(nt_status))
				return NULL;

			nt_status = reinterpret_cast<decltype(&NtMapViewOfSection)>(nt_map_view_of_secthion)(secthion_handle, NtCurrentProcess, &mapped_module, NULL, NULL, nullptr,
				&viewSize, (SECTION_INHERIT)1, NULL, PAGE_READONLY);

			if (!NT_SUCCESS(nt_status))
			{
				if (secthion_handle)
					reinterpret_cast<decltype(&NtClose)>(nt_close)(secthion_handle);
				return NULL;
			}
			if (secthion_handle && mapped_module)
			{ 
				functhion_address = crt_wrapper::get_proc_address(mapped_module, hahs_str);
				if (!functhion_address)
					functhion_address = crt_wrapper::get_address_by_rva(name_module, mapped_module, hahs_str);
#ifdef _WIN64 
				if (process_platrorm == PROCESS_64 && functhion_address)
				{
					ci.features = NULL;
					ci.code = reinterpret_cast<uint8_t*>(functhion_address);
					ci.codeLen = 0x20;//Safe min lenght need
					ci.dt = Decode64Bits;

					if (distorm_decompose(&ci, decode_instr, 100, &count_decode) != DECRES_INPUTERR)
					{
						for (uint32_t i = NULL; i < count_decode ; i++)
						{
							if (
								decode_instr[i].flags != FLAG_NOT_DECODABLE &&
								decode_instr[i].opcode == I_MOV &&
								decode_instr[i].ops[0].index == R_R10 &&
								decode_instr[i].ops[1].index == R_RCX &&

								decode_instr[i + 1].flags != FLAG_NOT_DECODABLE &&
								decode_instr[i + 1].opcode == I_MOV &&
								decode_instr[i + 1].ops[0].index == R_EAX &&

								((decode_instr[i + 2].flags != FLAG_NOT_DECODABLE &&
								decode_instr[i + 2].opcode == I_SYSCALL) ||
								(decode_instr[i + 4].flags != FLAG_NOT_DECODABLE &&
								decode_instr[i + 4].opcode == I_SYSCALL))
								)
							{
								syscall_number = decode_instr[i + 1].imm.dword;
								break;
							}
						}
					}
				}
#else
				ci.features = NULL;
				ci.code = reinterpret_cast<uint8_t*>(functhion_address);
				ci.codeLen = MAXIMUM_INSTRUCTION_SIZE;
				ci.dt = Decode32Bits;

				/*
				* WoW64:
				* Windows 10
				 | B8 9F010000                        | mov eax,19F
				 | BA 408B5D77                        | mov edx,ntdll.775D8B40
				 | FFD2                               | call edx
				 | C2 1000
				 | ret 10

				 X32 windows 10
				 B8 9B 00 00 00                       | mov     eax, 9Bh 													; RtlGetNativeSystemInformation
				 E8 03 00 00 00                       | call    sub_6A290E8D  via call $+8
				 C2 10 00                             | retn    10h
				 8B D4                                | mov     edx, esp
				 0F 34                                | sysenter
				 C3                                   | retn
				*/
				if (process_platrorm == PROCESS_WOW64 && functhion_address)
				{

					if (distorm_decompose(&ci, decode_instr, 100, &count_decode) != DECRES_INPUTERR)
					{
						for (uint32_t i = NULL; i < count_decode; i++)
						{
							if (
								decode_instr[i].flags != FLAG_NOT_DECODABLE &&
								decode_instr[i].opcode == I_MOV &&
								decode_instr[i].ops[0].index == R_EAX &&
								decode_instr[i].size == 0x5
								)
							{
								//Not dword for get correct number(thank's microsoft)
								syscall_number = decode_instr[i].imm.sword;
								break;
							}
						}
					}
				}
				else if (process_platrorm == PROCESS_32 && functhion_address)
				{
					if (distorm_decompose(&ci, decode_instr, 100, &count_decode) != DECRES_INPUTERR)
					{
						for (uint32_t i = NULL; i < count_decode; i++)
						{

							if (
								decode_instr[i].flags != FLAG_NOT_DECODABLE &&
								decode_instr[i].opcode == I_MOV &&
								decode_instr[i].ops[0].index == R_EAX &&
								decode_instr[i].size == 0x5
								)
							{
								syscall_number = decode_instr[i].imm.dword;
								break;
							}
						}
					}
				}


#endif // _WIN64 
				if (secthion_handle)
					reinterpret_cast<decltype(&NtClose)>(nt_close)(secthion_handle);
				if (mapped_module && NT_SUCCESS(nt_status))
					reinterpret_cast<decltype(&NtUnmapViewOfSection)>(nt_unmap_view_of_secthion)(NtCurrentProcess, mapped_module);
				if (allocate_file)
				{
					crt_wrapper::free(allocate_file);
					allocate_file = NULL;
				}
				if (file)
					reinterpret_cast<decltype(&NtClose)>(nt_close)(file);
			}
			return syscall_number;
		}

	};
}
#endif // !SYSCALL_DUMPER_ENABLE