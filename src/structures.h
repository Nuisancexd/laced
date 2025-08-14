#ifndef _DATA_STRUCTURES_H_
#define _DATA_STRUCTURES_H_


#include <cstdlib>
#include "macro.h"
#include <mutex>

#define PTR(elm) (void*&)elm


#define SLIST_ENTRY(type) type* entries;

#define SLIST_FOREACH(entry, c_elm)										\
		for(entry = c_elm->ptr; entry; entry = entry->entries)


/* Singly-Linked List */
template<typename TYPE>
class SLIST
{
public:

	TYPE* ptr = NULL;	/*  HEAD  */
	inline STATIC std::mutex mtx;

	~SLIST()
	{
		SLIST_DESTROY();
		delete ptr;
	}

	SLIST<TYPE>& operator=(SLIST<TYPE>& slist)
	{
		if (this == &slist || slist.SLIST_EMPTY())
			return *this;

		SLIST_DESTROY();

		TYPE* next = NULL;
		while (!slist.SLIST_EMPTY())
		{
			next = slist.SLIST_NEXT(slist.ptr);
			SLIST_INSERT_HEAD(slist.ptr);
			slist.ptr = next;
		}
		slist.ptr = NULL;
		return *this;
	}

	BOOL SLIST_EMPTY() CONST
	{
		return ptr == NULL;
	}

	VOID* SLIST_HEAD() CONST
	{
		return ptr;
	}

	VOID SLIST_CONCAT(SLIST* slist)
	{
		TYPE* next = NULL;
		while (!slist->SLIST_EMPTY())
		{
			next = slist->SLIST_NEXT(slist->ptr);
			SLIST_INSERT_HEAD(slist->ptr);
			slist->ptr = next;
		}
	}

	TYPE* SLIST_NEXT(TYPE*& entry) CONST
	{
		if (!SLIST_EMPTY())
			return entry->entries;
		return NULL;
	}


	inline VOID SLIST_INSERT_HEAD(TYPE*& entry)
	{
		entry->entries = ptr;
		ptr = entry;
	}

	VOID SLIST_INSERT_HEAD_SAFE(TYPE*& entry)
	{
		std::lock_guard<std::mutex> lock(mtx);
		entry->entries = ptr;
		ptr = entry;		
	}

	inline VOID SLIST_DELETE_HEAD(TYPE*& entry)
	{
		ptr = entry->entries;
		delete entry;
	}

	/*	not from head  */
	inline VOID SLIST_REMOVE_ELM(TYPE*& entry_ptr)
	{
		TYPE* p_elm = NULL;
		TYPE* prev = NULL;
		for (p_elm = (TYPE*)SLIST_HEAD(); p_elm; p_elm = p_elm->entries)
		{
			if (p_elm == entry_ptr)
			{
				p_elm = p_elm->entries;
				if (p_elm != NULL)
					prev->entries = p_elm;
				break;
			}
			prev = p_elm;
		}
		delete entry_ptr;
	}


	template<typename T, typename F>
	inline TYPE* LIST_FIND_ELM(T F::* field, const T& entry_ptr)
	{
		TYPE* p_elm = NULL;
		for (p_elm = (TYPE*)SLIST_HEAD(); p_elm; p_elm = p_elm->entries)
		{
			if (p_elm->*field == entry_ptr)
			{
				return p_elm;
			}
		}
		return NULL;
	}

private:
	VOID SLIST_DESTROY()
	{
		TYPE* p_elm = NULL;
		while (!SLIST_EMPTY())
		{
			p_elm = (TYPE*)SLIST_HEAD();
			ptr = p_elm->entries;
			delete p_elm;
		}
		ptr = NULL;
	}
};



#define LIST_ENTRY(type) struct{type* next; type* prev;}

#define LIST_FOREACH(entry, c_elm)										\
		for(entry = c_elm->ptr; entry; entry = entry->next)

#define REV_LIST_FOREACH(entry, c_elm)									\
		for(entry = c_elm->tptr; entry; entry = entry->prev)			

/*	Double-Linked List	*/
template<typename TYPE>
class LIST
{
public:

	TYPE* ptr = NULL;	/*	HEAD  */
	TYPE* tptr = NULL;	/*	TAIL  */

	~LIST()
	{
		LIST_DESTROY();
		delete ptr;
	}

	LIST<TYPE>& operator=(LIST<TYPE>& list)
	{
		if (this == &list || list.LIST_EMPTY())
			return *this;

		LIST_DESTROY();

		TYPE* next = NULL;
		while (!list.LIST_EMPTY())
		{
			next = list.LIST_NEXT(list.ptr);
			LIST_INSERT_HEAD(list.ptr);
			list.ptr = next;
		}

		return *this;
	}

	BOOL LIST_EMPTY() CONST
	{
		return ptr == NULL;
	}

	VOID* LIST_HEAD() CONST
	{
		return ptr;
	}

	TYPE* LIST_HEAD_T() CONST
	{
		return ptr;
	}

	VOID* LIST_TAIL() CONST
	{
		return tptr;
	}

	TYPE* LIST_NEXT(TYPE*& entry) CONST
	{
		if (!LIST_EMPTY())
			return entry->next;
		return NULL;
	}

	TYPE* LIST_PREV(TYPE*& entry) CONST
	{
		if (!LIST_EMPTY())
			return entry->prev;
		return NULL;
	}

	inline VOID LIST_CONCAT_HEAD(LIST*& list)
	{
		list->tptr->next = ptr;
		ptr->prev = list->tptr;
		ptr = list->ptr;
	}

	inline VOID LIST_CONCAT_TAIL(LIST*& list)
	{
		tptr->next = list->ptr;
		list->ptr->prev = tptr;
		tptr = list->tptr;
	}

	inline VOID LIST_INSERT_HEAD(TYPE*& entry)
	{
		if ((entry->next = ptr) != NULL)
		{
			ptr->prev = entry;
		}
		else
		{
			tptr = entry;
		}
		ptr = entry;
		entry->prev = NULL;
	}

	inline VOID LIST_INSERT_TAIL(TYPE*& entry)
	{
		if ((entry->prev = tptr) != NULL)
		{
			tptr->next = entry;
		}
		tptr = entry;
		entry->next = NULL;
	}

	inline VOID LIST_INSERT_AFTER(TYPE*& entry, TYPE*& after_entry)
	{
		if (entry->next != NULL)
		{
			after_entry->prev = entry;
			after_entry->next = entry->next;
			entry->next->prev = after_entry;
			entry->next = after_entry;
		}
	}

	inline VOID LIST_INSERT_BEFORE(TYPE*& entry, TYPE*& before_entry)
	{
		if (entry->prev != NULL)
		{
			before_entry->next = entry;
			before_entry->prev = entry->prev;
			entry->prev->next = before_entry;
			entry->prev = before_entry;
		}
	}

	template<typename T, typename F>
	inline TYPE* LIST_FIND_ELM(T F::* field, const T& entry_ptr)
	{
		TYPE* p_elm = NULL;
		for (p_elm = (TYPE*)LIST_HEAD(); p_elm; p_elm = p_elm->next)
		{
			if (p_elm->*field == entry_ptr)
			{
				return p_elm;
			}
		}
		return NULL;
	}

	inline VOID LIST_DELETE_HEAD()
	{
		TYPE* f_ptr = LIST_HEAD_T();
		ptr = ptr->next;
		if (ptr)
			ptr->prev = NULL;
		delete f_ptr;
	}

	inline VOID LIST_DELETE_TAIL()
	{
		TYPE* f_tptr = LIST_TAIL();
		tptr = tptr->prev;
		tptr->next = NULL;
		delete f_tptr;
	}

	/*	NOT FROM HEAD & TAIL */
	inline VOID LIST_DELETE_ELM(TYPE*& entry_ptr)
	{
		entry_ptr->prev->next = entry_ptr->next;
		entry_ptr->next->prev = entry_ptr->prev;
		delete entry_ptr;
	}

private:
	VOID LIST_DESTROY()
	{
		TYPE* p_elm = NULL;
		while (!LIST_EMPTY())
		{
			p_elm = (TYPE*)LIST_HEAD();
			ptr = p_elm->next;
			delete p_elm;
		}
		tptr = NULL;
	}
};




#define STQUEUE_ENTRY(type) type* next

#define STQUEUE_FOREACH(entry, c_elm)	\
	for(entry = c_elm->ptr; entry; entry = entry->next)


/* Single Linked Tail Queue */
template<typename TYPE>
class STQUEUE
{
public:

	TYPE* ptr = NULL;	/*	HEAD  */
	TYPE** tptr = &ptr;

	~STQUEUE()
	{
		STQUEUE_DESTROY();
		delete ptr;
	}


	STQUEUE& operator=(STQUEUE* sque)
	{
		while (sque->STQUEUE_HEAD())
		{
			*tptr = (TYPE*)sque->STQUEUE_HEAD();
			tptr = (TYPE**)sque->STQUEUE_TAIL();
			sque->ptr = NULL;
			sque->tptr = &sque->ptr;
		}
		return *this;
	}

	VOID* STQUEUE_HEAD() CONST
	{
		return ptr;
	}

	VOID* STQUEUE_TAIL() CONST
	{
		return *tptr;
	}

	BOOL STQUEUE_EMPTY() CONST
	{
		return ptr == NULL;
	}

	TYPE* STQUEUE_NEXT(TYPE*& entry) CONST
	{
		if (!STQUEUE_EMPTY())
			return entry->next;
		return NULL;
	}

	VOID STQUEUE_CONCAT(STQUEUE*& head)
	{
		while (head->ptr != NULL)
		{
			*tptr = head->ptr;
			tptr = head->tptr;
			head->ptr = NULL;
			head->tptr = &head->ptr;
		}
	}

	VOID STQUEUE_INSERT_HEAD(TYPE*& entry)
	{
		if ((entry->next = ptr) == NULL)
		{
			tptr = &entry->next;
		}
		ptr = entry;
	}

	VOID STQUEUE_INSERT_TAIL(TYPE*& entry)
	{
		entry->next = NULL;
		*tptr = entry;
		tptr = &entry->next;
	}

	VOID STQUEUE_INSERT_AFTER(TYPE*& after_entry, TYPE*& entry_ptr)
	{
		if ((after_entry->next = entry_ptr->next) == NULL)
		{
			tptr = &after_entry->next;
		}
		entry_ptr->next = after_entry;
	}


	VOID STQUEUE_DELETE_HEAD()
	{
		VOID* f_ptr = ptr;
		if ((ptr = ptr->next) == NULL)
		{
			tptr = &ptr;
		}
		free(f_ptr);
	}

private:
	VOID STQUEUE_DESTROY()
	{
		while (STQUEUE_HEAD() != NULL)
		{
			STQUEUE_DELETE_HEAD();
		}
	}
};





#endif