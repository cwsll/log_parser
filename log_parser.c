
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define BUFFER_SIZE 512
#define MAX_KEYWORDS 16

const char *default_keywords[] = {
    "FAILED", "404", "DENIED", "ERROR"
};

int search_word(char line[], const char word[])
{
    int i, j;

    for (i = 0; line[i] != '\0'; i++) {

        for (j = 0; word[j] != '\0'; j++) {

            if (line[i + j] == '\0')
                break;

            if (tolower((unsigned char)line[i + j]) !=
                tolower((unsigned char)word[j]))
                break;
        }

        if (word[j] == '\0')
            return 1;
    }

    return 0;
}

void show_help(char name[])
{
    printf("\n========== LOG ANALYZER ==========\n");
    printf("Usage: %s <log_file> [keyword ...]\n\n", name);
    printf("Searches log files for suspicious keywords.\n");
    printf("Search is not case-sensitive.\n\n");
    printf("Default keywords: FAILED, 404, DENIED, ERROR\n");
    printf("Maximum keywords: %d\n", MAX_KEYWORDS);
    printf("==================================\n");
}

int main(int argc, char *argv[])
{
    char line[BUFFER_SIZE];
    const char *keyword;
    FILE *file_pointer;

    unsigned long line_number = 0;
    unsigned long alerts = 0;

    int keyword_count;
    int i;

    if (argc < 2) {
        printf("Error: Please enter a log file name.\n");
        show_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "--help") == 0) {
        show_help(argv[0]);
        return 0;
    }

    if (argc > 2) {
        keyword_count = argc - 2;
    }
    else {
        keyword_count = sizeof(default_keywords) /
                        sizeof(default_keywords[0]);
    }

    if (keyword_count > MAX_KEYWORDS) {
        printf("Error: Maximum %d keywords allowed.\n", MAX_KEYWORDS);
        return 1;
    }

    file_pointer = fopen(argv[1], "r");

    if (file_pointer == NULL) {
        perror("Cannot open file");
        return 1;
    }

    printf("\n========== LOG FILE ANALYZER ==========\n");
    printf("File: %s\n", argv[1]);
    printf("Keywords: ");

    for (i = 0; i < keyword_count; i++) {

        if (argc > 2)
            keyword = argv[i + 2];
        else
            keyword = default_keywords[i];

        printf("%s ", keyword);
    }

    printf("\n=======================================\n\n");

    while (fgets(line, sizeof(line), file_pointer) != NULL) {

        line_number++;

        for (i = 0; i < keyword_count; i++) {

            if (argc > 2)
                keyword = argv[i + 2];
            else
                keyword = default_keywords[i];

            if (search_word(line, keyword)) {

                alerts++;

                line[strcspn(line, "\r\n")] = '\0';

                printf("[ALERT] Line %-5lu | %-8s | %s\n",
                       line_number, keyword, line);

                break;
            }
        }
    }

    if (ferror(file_pointer)) {
        printf("\nError: Failed to read the file.\n");
        fclose(file_pointer);
        return 1;
    }

    fclose(file_pointer);

    printf("\n========== ANALYSIS REPORT ==========\n");
    printf("File checked : %s\n", argv[1]);
    printf("Total lines  : %lu\n", line_number);
    printf("Total alerts : %lu\n", alerts);
    printf("=====================================\n");

    if (alerts == 0)
        printf("Result: No suspicious activity found.\n");
    else
        printf("Result: Suspicious activity detected!\n");

    return 0;
}
