#include "mac.h"
#include "log.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

mac_port_map_t mac_port_map;

uint8_t hash_val(u8 mac[ETH_ALEN])
{
	uint8_t val = 0;
	for (int i = 0; i < ETH_ALEN; ++i)
		val ^= mac[i];
	return val;
}

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++)
	{
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++)
	{
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list)
		{
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	// fprintf(stdout, "TODO: implement the lookup process here.\n");

	uint8_t index = hash_val(mac);
	mac_port_entry_t *entry = NULL;
	pthread_mutex_lock(&mac_port_map.lock);
	list_for_each_entry(entry, &mac_port_map.hash_table[index], list)
	{
		int b = memcmp(mac, entry->mac, ETH_ALEN);
		if (b == 0)
		{
			entry->visited = time(NULL);
			pthread_mutex_unlock(&mac_port_map.lock);
			return entry->iface;
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	// fprintf(stdout, "TODO: implement the insertion process here.\n");
	iface_info_t *forward_iface = lookup_port(mac);
	// already existed
	if (forward_iface != NULL)
		return;
	// not exist, insert
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *new_entry = malloc(sizeof(mac_port_entry_t));
	new_entry->iface = iface;
	memcpy(new_entry->mac, mac, ETH_ALEN);
	new_entry->visited = time(NULL);
	list_add_tail(&new_entry->list, &mac_port_map.hash_table[hash_val(mac)]);
	pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++)
	{
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list)
		{
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac),
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	// fprintf(stdout, "TODO: implement the sweeping process here.\n");
	int count = 0;
	time_t now = time(NULL);
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++)
	{
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list)
		{
			if ((int)(now - entry->visited) >= MAC_PORT_TIMEOUT)
			{
				list_delete_entry(&entry->list);
				free(entry);
				++count;
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return count;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1)
	{
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
