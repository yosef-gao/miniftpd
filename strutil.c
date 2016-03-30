#include "strutil.h"
#include "common.h"

#define ISSPACE(x) ((x)==' '||(x)=='\r'||(x)=='\n'||(x)=='\f'||(x)=='\b'||(x)=='\t')

void str_trim_crlf(char *str)
{
    char *p = &str[strlen(str) - 1];
    while (*p == '\r' || *p == '\n')
        *p-- = '\0';
}

void str_split(const char *str, char *left, char *right, char c)
{
    char *p = strchr(str, c);
    if (p == NULL)
    {
        strcpy(left, str);
    }
    else
    {
        strncpy(left, str, p - str);
        strcpy(right, p + 1);
    }
}

int str_all_space(const char *str)
{
    while (*str)
    {
        if (!isspace(*str))
            return 0;
        str++;
    }
    return 1;
}

void str_upper(char *str)
{
    while (*str)
    {
        *str = toupper(*str);
        str++;
    }
}

long long str_to_longlong(const char *str)
{
    // return atoll(str);
    /* warning not all systems support this function */
    long long tmp = 0;
    size_t len = strlen(str), i = 0;

    /* our function only support long long len less than 15*/
    if (len > 15)
        return 0;

    for (i = 0; i < len; ++i)
    {
        if (str[i] < '0' || str[i] > '9')
            return 0;
        tmp *= 10;
        tmp += str[i] - '0';
    }
    return tmp;
}

unsigned int str_octal_to_uint(const char *str)
{
    unsigned int tmp = 0;
    size_t len = strlen(str), i = 0;

    if (len > 10)
        return 0;

    while (str[i])
    {
        if (str[i] != '0')
            break;
        else
            ++i;
    }

    for (i = 0; i < len; ++i)
    {
        if (str[i] < '0' || str[i] > '8')
            return 0;
        tmp *= 8;
        tmp += str[i] - '0';
    }
    return tmp;
}


char* trim(char* str)
{
    char *tail, *head;
    for (tail = str + strlen(str) - 1; tail >= str; tail --)
        if (!ISSPACE(*tail))
            break;

    tail[1] = 0;
    for (head = str; head <= tail; head ++)
        if (!ISSPACE(*head))
            break;
    
    if (head != str)
        memcpy(str, head, (tail - head + 2) * sizeof(char));

    return str; 
}
