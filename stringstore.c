#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct StringStore {
    char* key;
    char* value;
    struct StringStore* next;
} StringStore;

StringStore* stringstore_init(void) {
    StringStore* head = (StringStore*) calloc(1, sizeof(StringStore));
    if (head == NULL) {
	exit(1);
    }
    head->key = NULL;
    head-> value = NULL;
    head->next = NULL;
    return head;
}

StringStore* stringstore_free(StringStore* store) {
    while (store != NULL) {
	StringStore* tmp = store->next;
	if (store->key) { // Not the first node
	    free(store->key);
	    free(store->value);
	}
	free(store);
	store = tmp;
    }
    return NULL;
}

int stringstore_add(StringStore* store, const char* key, const char* value) {
    while (1) {
	if (store->key) {
	    if (!strcmp(store->key, key)) {
		store->value = strdup(value);
		if (!store->value) {
		    return 0;
		}
		return 1;
	    }
	}
	if (store->next == NULL) {
	    break;
	}
	store = store->next;
    }
    StringStore* next = (StringStore *) calloc(1, sizeof(StringStore));
    store->next = next;
    next->key = strdup(key);
    next->value = strdup(value);
    next->next = NULL;
    store = next;
    
    if (!(store->key) || !(store->value)) {
	return 0;
    }
    return 1;
}

const char* stringstore_retrieve(StringStore* store, const char* key) {
    for (StringStore* tmp = store; tmp != NULL; tmp = tmp->next) {
	if (!(tmp->key)) { // Head Node
	    continue;
	}
	if (!strcmp(tmp->key, key)) {
	    return tmp->value;
	}
    }
    return NULL; // None found.dd
}

int stringstore_delete(StringStore* store, const char* key) {
    StringStore* prev = store;
    for (StringStore* tmp = store; tmp != NULL; tmp = tmp->next) {
	if (!(tmp->key)) { // Head node
	    continue;
	}
	if (!strcmp(tmp->key, key)) {
	    prev->next = tmp->next;
	    free(tmp->key);
	    free(tmp->value);
	    free(tmp);
	    return 1;
	}
	prev = tmp;
    }
    return 0;
}
