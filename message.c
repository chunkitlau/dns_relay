#include "message.h"

static unsigned int hash(unsigned char *buffer, unsigned int question_size) {
    unsigned int hash = 0;
    for (int k = 0; k < question_size; ++k) {
        hash = hash * PRIME1 + ((!hash_ignore[k]) ? buffer[k] : 256);
    }
    return hash;
}

Message *new_message(unsigned char *buffer, unsigned int buffer_size, unsigned int question_size, unsigned long ttl) {
    Message* message = (Message *)malloc(sizeof(Message));
    message->buffer_size = buffer_size;
    message->buffer = (unsigned char *)malloc(message->buffer_size * sizeof(unsigned char));
    memcpy(message->buffer, buffer, message->buffer_size);
    message->question_size = question_size;
    message->ttl = ttl;
    message->hash = hash(buffer, question_size);
    return message;
}

void delete_message(Message *message) {
    free(message->buffer);
    free(message);
}

void new_message_map() {
    for (int k = 0; k < 12; ++k) hash_ignore[k]= 1;
    message_map = (Message_node **)malloc(cache_size * sizeof(Message_node *));
    for (int k = 0; k < cache_size; ++k) {
        message_map[k] = (Message_node *)malloc(sizeof(Message_node));
        message_map[k]->next_message_node = NULL;
    }
}

void delete_message_map() {
    for (int k = 0; k < cache_size; ++k) {
        for (Message_node *p = message_map[k]->next_message_node; p; p =  message_map[k]->next_message_node) {
            message_map[k]->next_message_node = p->next_message_node;
            free(p);
        }
        free(message_map[k]);
    }
    free(message_map);
}

static int between(unsigned int a, unsigned int b, unsigned int c) {
    return ((a <= b) && (b < c)) || ((c < a) && (a <= b)) || ((b < c) && (c < a));
}

Message_node *message_map_find(Message *message) {
    int index = message->hash % cache_size;
    Message_node *message_node = message_map[index];
    while(message_node->next_message_node && message_node->next_message_node->message->hash != message->hash) {
        if (message_node->next_message_node->message->ttl == ULONG_MAX ||
            between(message_map_dynamic_id - dynamic_size, message_node->next_message_node->id, message_map_dynamic_id + 1)) {
                message_node = message_node->next_message_node;
        }
        else {
            //printf("delete message_node id %u\n", message_node->next_message_node->id);
            Message_node *message_node_p = message_node->next_message_node;
            message_node->next_message_node = message_node->next_message_node->next_message_node;
            delete_message(message_node_p->message);
            free(message_node_p);
        }
    }
    if (message_node->next_message_node) {
        message_node->next_message_node->id = ++message_map_dynamic_id;
    }
    return message_node;
}

void message_map_insert(Message *message) {
    Message_node *message_node = message_map_find(message);
    message_node->next_message_node = (Message_node *)malloc(sizeof(Message_node));
    message_node->next_message_node->message = message;
    message_node->next_message_node->next_message_node = NULL;
    if (message->ttl != ULONG_MAX) {
        message_node->next_message_node->id = ++message_map_dynamic_id;
        //printf("message_map_dynamic_id: %u\n", message_map_dynamic_id);
    }
}