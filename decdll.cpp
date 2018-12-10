// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <emmintrin.h>
#include <iostream>

#define _CRT_SECURE_NO_WARNINGS

// v11 = sub_180152F08(v10, v13, 1, a4);
void * sub_180152F08(void *Src, __int64 a2, int a3, size_t *a4)
{
	size_t *v4; // rbp
	void *v5; // rsi
	size_t v6; // rdi
	unsigned __int64 v7; // rdx
	unsigned __int64 v8; // rdi
	void *v9; // rbx

	v4 = a4;
	v5 = Src;
	v6 = 4 * a2;
	if (!a3)
		goto LABEL_5;
	v7 = *((unsigned int *)Src + a2 - 1);
	v8 = v6 - 4;
	if (v7 >= v8 - 3 && v7 <= v8)
	{
		v6 = (unsigned int)v7;
	LABEL_5:
		v9 = malloc(v6 + 1);
		memmove(v9, v5, v6);
		*((unsigned char *)v9 + v6) = 0;
		*v4 = v6;
		return v9;
	}
	return 0i64;
}

// v10 = sub_1801530C0((unsigned int *)v7, v13, v8);
unsigned int * sub_1801530C0(unsigned int *a1, unsigned int a2, __int64 a3)
{
	unsigned int v3; // esi
	int v4; // er11
	unsigned int v5; // er9
	int v6; // ebp
	unsigned int v7; // ebx
	__int64 v8; // r12
	unsigned int *v9; // r14
	char v10; // al
	bool v11; // zf

	v3 = *a1;
	v4 = a2 - 1;
	v5 = -1640531527 * (0x34 / a2 + 6);
	if (a2 - 1 >= 1 && v5)
	{
		do
		{
			v6 = a2 - 1;
			v7 = (v5 >> 2) & 3;
			if (a2 != 1)
			{
				v8 = (unsigned int)v4;
				v9 = &a1[v4];
				do
				{
					v10 = v8--;
					*v9 -= ((v3 ^ v5) + (*(v9 - 1) ^ *(unsigned int *)(a3 + 4 * (v7 ^ (unsigned __int64)(v10 & 3))))) ^ ((4 * v3 ^ (*(v9 - 1) >> 5)) + ((v3 >> 3) ^ 16 * *(v9 - 1)));
					v3 = *v9;
					--v9;
					--v6;
				} while (v6);
			}
			*a1 -= ((v3 ^ v5) + (a1[v4] ^ *(unsigned int *)(a3 + 4 * (v7 ^ (unsigned __int64)(v6 & 3))))) ^ ((4 * v3 ^ (a1[v4] >> 5))
				+ ((v3 >> 3) ^ 16 * a1[v4]));
			v11 = v5 == -1640531527;
			v5 += 1640531527;
			v3 = *a1;
		} while (!v11);
	}
	return a1;
}

// v7 = sub_180152E6C(a1, a2, 0, (size_t *)&v13);
void* sub_180152E6C(void *Src, size_t Size, int a3, size_t *a4)
{
	size_t v4; // rbp
	size_t *v5; // r12
	void *v6; // r13
	size_t v7; // rdi
	void *v8; // rax
	void *v9; // rbx

	v4 = Size;
	v5 = a4;
	v6 = Src;
	v7 = (Size >> 2) + 1;
	if (!(Size & 3))
		v7 = Size >> 2;
	if (a3)
	{
		v8 = calloc(v7 + 1, 4ui64);
		v9 = v8;
		if (!v8)
			return 0i64;
		*((unsigned int *)v8 + v7) = v4;
		*v5 = v7 + 1;
	}
	else
	{
		v9 = calloc(v7, 4ui64);
		if (!v9)
			return 0i64;
		*v5 = v7;
	}
	memmove(v9, v6, v4);
	return v9;
}

// return sub_180153294(v7, v6, &Dst, v5);
void* sub_180153294(void *a1, size_t a2, void *a3, size_t *a4)
{
	void *v5; // rbx
	void *v7; // rdi
	void *v8; // rax
	void *v9; // rsi
	unsigned int *v10; // rax
	void *v11; // rbx
	char v12; // [rsp+20h] [rbp-18h]
	__int64 v13; // [rsp+48h] [rbp+10h]

	v5 = a3;
	if (!a2)
		return 0i64;
	v7 = sub_180152E6C(a1, a2, 0, (size_t *)&v13);
	if (!v7)
		return 0i64;
	v8 = sub_180152E6C(v5, 0x10u, 0, (size_t *)&v12);
	v9 = v8;
	if (!v8)
	{
		free(v7);
		return 0i64;
	}
	v10 = sub_1801530C0((unsigned int *)v7, v13, (__int64)v8);
	v11 = sub_180152F08(v10, v13, 1, a4);
	free(v7);
	free(v9);
	return v11;
}

// void * sub_1801533C0(void *v8, unsigned int Size, "8moQs6YuA2VnNzNLuftq5XWqUJncQyZRSOn3xFZ4mFB5wWMWqui5UjuYJ60JwtD8", &Size);
void* sub_1801533C0(void* a1, __int64 a2, __m128i *a3, size_t *a4)
{
	unsigned __int64 v4; // rax
	unsigned __int64 v8; // rax
	__m128i Dst; // [rsp+20h] [rbp-38h]

	v4 = 0i64;
	_mm_storeu_si128((__m128i *)&Dst, *a3);
	do
	{
		if (!*((unsigned char *)&Dst + v4))
			break;
		++v4;
	} while (v4 < 0x10);
	v8 = v4 + 1;
	if (v8 < 0x10)
		memset((char *)&Dst + v8, 0, 16 - v8);
	return sub_180153294(a1, a2, &Dst, a4);
}

void fileWrite(const char* pData, size_t uSize)
{
	FILE * pFile;
	pFile = fopen("dec.dll", "wb");
	fwrite(pData, sizeof(char), uSize, pFile);
	fclose(pFile);
}

char * fileRead(const char* pPath, size_t * pSize)
{
	char * pData = NULL;
	FILE * pFile;
	long lSize;

	pFile = fopen(pPath, "rb");
	if (pFile == NULL) { fputs("File error", stderr); exit(1); }

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	pData = (char*)malloc(sizeof(char)*lSize);
	if (pData == NULL) { fputs("Memory error", stderr); exit(2); }

	// copy the file into the buffer:
	*pSize = fread(pData, 1, lSize, pFile);
	if (*pSize != lSize) { fputs("Reading error", stderr); exit(3); }

	/* the whole file is now loaded in the memory buffer. */

	// terminate
	fclose(pFile);
	return pData;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		std::cout << argv[0] << " file.dll" << std::endl;
		return 0;
	}

	size_t uSize = 0;
	char * pData = fileRead(argv[1], &uSize);

	size_t uDecSize = 0;
	char * pDecData = NULL;
	pDecData = (char *)sub_1801533C0(pData, uSize, (__m128i *)"8moQs6YuA2VnNzNLuftq5XWqUJncQyZRSOn3xFZ4mFB5wWMWqui5UjuYJ60JwtD8", &uDecSize);
	if (pDecData == NULL) {
		std::cout << " dec error !!! " << std::endl;
		std::cin >> uSize;
		return 0;
	}
	fileWrite(pDecData, uDecSize);

	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
