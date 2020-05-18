//
// Created by root on 2020/5/14.
//
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
int count;
void listDir(char *path) {
    DIR *pDir;
    struct dirent *ent;

    pDir = opendir(path);

    while ((ent = readdir(pDir)) != NULL) {

        if (ent->d_type & DT_DIR) {

            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;
        } else
            printf("name:%s\n", ent->d_name);

    }
}

int main() {
    count = 0;
    while (1) {
        sleep(10);
        listDir("/home/packets");
    }
    return 0;
}
