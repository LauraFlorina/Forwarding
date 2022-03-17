#include "table_parser.h"

FILE *open_file(char *file_name) {
	FILE *fp = fopen(file_name, "r");
	DIE(fp== NULL, "open file");
	return fp;
}

int read_rtable(struct route_table_entry *rtable, char *file_name) {
	int i = 0;
	FILE *fp = open_file(file_name);
	char *row = malloc(ROW_LEN);
	DIE(row == NULL, "memory");
	char *word;
	while (fgets(row, ROW_LEN, fp) != NULL) {
		// prefix
		word = strtok(row, " \n");
		DIE(word == NULL, "null token");
		rtable[i].prefix = inet_addr(word);
		// next_hop
		word = strtok(NULL, " \n");
		DIE(word == NULL, "null token");
		rtable[i].next_hop = inet_addr(word);
		// mask
		word = strtok(NULL, " \n");
		DIE(word == NULL, "null token");
		rtable[i].mask = inet_addr(word);
		// interface
		word = strtok(NULL, " \n");
		DIE(word == NULL, "null token");
		rtable[i].interface = atoi(word);

		i++;
	}
   	free(row);
    fclose(fp);
    return i;
}