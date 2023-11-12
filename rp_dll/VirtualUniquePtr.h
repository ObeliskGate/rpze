#pragma once

template <typename T>
class VirtualUniquePtr
{
	T* ptr;
public:
	VirtualUniquePtr(size_t size = 1)
	{
		this->ptr = static_cast<T*>(VirtualAlloc(nullptr, size * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	}
	VirtualUniquePtr(VirtualUniquePtr&& other) noexcept : ptr(other.ptr) { other.ptr = nullptr; }
	VirtualUniquePtr(VirtualUniquePtr& other) = delete;
	VirtualUniquePtr& operator=(VirtualUniquePtr& other) = delete;
	VirtualUniquePtr& operator=(VirtualUniquePtr&& other) noexcept
	{
		if (this != &other) {
			VirtualFree(ptr, 0, MEM_RELEASE); 
			ptr = other.ptr; 
			other.ptr = nullptr;
		}
		return *this;
	}

	~VirtualUniquePtr();
	T* operator->() { return ptr; }
	T& operator*() { return *ptr; }
	T& operator[](size_t index) { return ptr[index]; }

	T* get() { return ptr; }
};

template <typename T>
VirtualUniquePtr<T>::~VirtualUniquePtr()
{
	VirtualFree(ptr, 0, MEM_RELEASE);
}
