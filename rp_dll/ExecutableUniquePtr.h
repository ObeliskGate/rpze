#pragma once
#include "pch.h"

class __HeapWrapper
{
	HANDLE hHeap;
public:
	HANDLE heap() const { return hHeap; }
	__HeapWrapper(DWORD flOptions) : hHeap(HeapCreate(flOptions, 0, 0)) {}
	~__HeapWrapper() { HeapDestroy(hHeap); }
};

inline static __HeapWrapper __hExecutableHeap(HEAP_CREATE_ENABLE_EXECUTE);

template <typename T>
class ExecutableUniquePtr
{
	T* ptr;
public:
	ExecutableUniquePtr(size_t size = 1);
	ExecutableUniquePtr(ExecutableUniquePtr&& other) noexcept : ptr(other.ptr) { other.ptr = nullptr; }
	ExecutableUniquePtr(ExecutableUniquePtr& other) = delete;
	ExecutableUniquePtr& operator=(ExecutableUniquePtr& other) = delete;
	ExecutableUniquePtr& operator=(ExecutableUniquePtr&& other) noexcept;
	~ExecutableUniquePtr();
	T* operator->() { return ptr; }
	T& operator*() { return *ptr; }
	const T& operator*() const { return *ptr;  }
	T& operator[](size_t index) { return ptr[index]; }
	const T& operator[](size_t index) const { return ptr[index]; }
	T* get() { return ptr; }
};

template <typename T>
ExecutableUniquePtr<T>::ExecutableUniquePtr(size_t size) : ptr(
	static_cast<T*>(HeapAlloc(__hExecutableHeap.heap(), 0, size)))
{
	if (!ptr) throw std::bad_alloc();
}

template <typename T>
ExecutableUniquePtr<T>& ExecutableUniquePtr<T>::operator=(ExecutableUniquePtr&& other) noexcept
{
	if (this != &other) {
		HeapFree(__hExecutableHeap.heap(), 0, ptr);
		ptr = other.ptr;
		other.ptr = nullptr;
	}
	return *this;
}

template <typename T>
ExecutableUniquePtr<T>::~ExecutableUniquePtr()
{
	HeapFree(__hExecutableHeap.heap(), 0, ptr);
}
