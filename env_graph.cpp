/*
 * EnvGraph runtime candidate support.
 *
 * M1 deliberately limits graph usage to concrete inbound payload replacement
 * for the current resource/message.  It does not graft schedules or create
 * file descriptors, so graph-assisted patches remain ordinary EnvFuzz patches.
 */

struct ENVGRAPH_CAND
{
    ENVGRAPH_CAND *next;
    const char *resource_key;
    size_t len;
    uint8_t *payload;
};

static ENVGRAPH_CAND *envgraph_cands = NULL;
static size_t envgraph_cand_count = 0;

static bool envgraph_enabled(void)
{
    return option_graphname != NULL && option_graphname[0] != '\0';
}

static const char *envgraph_skip_ws(const char *p, const char *end)
{
    while (p < end && isspace(*p))
        p++;
    return p;
}

static const char *envgraph_find_key(const char *start, const char *end,
    const char *key)
{
    PRINTER K;
    K.format("\"%s\"", key);
    size_t klen = strlen(K.str());
    for (const char *p = start; p + klen < end; p++)
    {
        if (memcmp(p, K.str(), klen) != 0)
            continue;
        p += klen;
        p = envgraph_skip_ws(p, end);
        if (p >= end || *p != ':')
            continue;
        return envgraph_skip_ws(p + 1, end);
    }
    return NULL;
}

static const char *envgraph_find_literal(const char *start, const char *end,
    const char *needle)
{
    size_t nlen = strlen(needle);
    for (const char *p = start; p + nlen <= end; p++)
    {
        if (memcmp(p, needle, nlen) == 0)
            return p;
    }
    return NULL;
}

static char *envgraph_parse_string(const char *p, const char *end)
{
    if (p == NULL || p >= end || *p != '"')
        return NULL;
    p++;
    char *buf = (char *)xmalloc((size_t)(end - p) + 1);
    size_t j = 0;
    while (p < end)
    {
        char c = *p++;
        if (c == '"')
        {
            buf[j] = '\0';
            return buf;
        }
        if (c != '\\')
        {
            buf[j++] = c;
            continue;
        }
        if (p >= end)
            break;
        c = *p++;
        switch (c)
        {
            case '"': case '\\': case '/':
                buf[j++] = c; break;
            case 'b':
                buf[j++] = '\b'; break;
            case 'f':
                buf[j++] = '\f'; break;
            case 'n':
                buf[j++] = '\n'; break;
            case 'r':
                buf[j++] = '\r'; break;
            case 't':
                buf[j++] = '\t'; break;
            case 'u':
                // EnvFuzz resource keys are expected to be ASCII-ish paths.
                // Preserve parser progress without trying to encode UTF-8.
                for (size_t i = 0; i < 4 && p < end; i++, p++)
                    ;
                buf[j++] = '?';
                break;
            default:
                buf[j++] = c; break;
        }
    }
    xfree(buf);
    return NULL;
}

static bool envgraph_parse_size(const char *p, const char *end, size_t *out)
{
    p = envgraph_skip_ws(p, end);
    if (p == NULL || p >= end || !isdigit(*p))
        return false;
    size_t x = 0;
    while (p < end && isdigit(*p))
    {
        x = x * 10 + (size_t)(*p - '0');
        p++;
    }
    *out = x;
    return true;
}

static int envgraph_hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *envgraph_decode_hex(const char *hex, size_t len)
{
    size_t hlen = strlen(hex);
    if (hlen != 2 * len)
        return NULL;
    uint8_t *payload = (uint8_t *)xmalloc(len == 0? 1: len);
    for (size_t i = 0; i < len; i++)
    {
        int hi = envgraph_hex(hex[2*i]);
        int lo = envgraph_hex(hex[2*i+1]);
        if (hi < 0 || lo < 0)
        {
            xfree(payload);
            return NULL;
        }
        payload[i] = (uint8_t)((hi << 4) | lo);
    }
    return payload;
}

static void envgraph_add(const char *resource_key, size_t len,
    uint8_t *payload)
{
    ENVGRAPH_CAND *C = (ENVGRAPH_CAND *)xmalloc(sizeof(*C));
    C->resource_key = resource_key;
    C->len          = len;
    C->payload      = payload;
    C->next         = envgraph_cands;
    envgraph_cands  = C;
    envgraph_cand_count++;
}

static void envgraph_load(void)
{
    if (!envgraph_enabled())
        return;

    int fd = open(option_graphname, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        error("failed to open EnvGraph \"%s\": %s", option_graphname,
            strerror(errno));
    struct stat st;
    if (fstat(fd, &st) < 0)
        error("failed to stat EnvGraph \"%s\": %s", option_graphname,
            strerror(errno));
    size_t size = (size_t)st.st_size;
    char *buf = (char *)xmalloc(size + 1);
    size_t off = 0;
    while (off < size)
    {
        ssize_t r = read(fd, buf + off, size - off);
        if (r < 0)
            error("failed to read EnvGraph \"%s\": %s", option_graphname,
                strerror(errno));
        if (r == 0)
            break;
        off += (size_t)r;
    }
    close(fd);
    buf[off] = '\0';

    const char *end = buf + off;
    const char *p = buf;
    while ((p = envgraph_find_literal(p, end, "\"payload_hex\"")) != NULL)
    {
        const char *obj = p;
        while (obj > buf && *obj != '{')
            obj--;
        const char *obj_end = p;
        while (obj_end < end && *obj_end != '}')
            obj_end++;
        if (obj >= p || obj_end >= end)
        {
            p++;
            continue;
        }

        char *resource_key = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "resource_key"), obj_end);
        char *payload_hex = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "payload_hex"), obj_end);
        size_t len = 0;
        bool ok_len = envgraph_parse_size(
            envgraph_find_key(obj, obj_end, "payload_len"), obj_end, &len);

        if (resource_key != NULL && payload_hex != NULL && ok_len && len > 0)
        {
            uint8_t *payload = envgraph_decode_hex(payload_hex, len);
            if (payload != NULL)
                envgraph_add(resource_key, len, payload);
            else
                xfree(resource_key);
        }
        else if (resource_key != NULL)
            xfree(resource_key);
        if (payload_hex != NULL)
            xfree(payload_hex);

        p = obj_end + 1;
    }

    xfree(buf);
    if (option_log >= 1)
        fprintf(stderr, "%sENVGRAPH%s %s candidates=%zu\n", MAGENTA, OFF,
            option_graphname, envgraph_cand_count);
}

static size_t envgraph_count_matches(const ENTRY *E, const MSG *M)
{
    if (!envgraph_enabled() || E == NULL || E->name == NULL || M->outbound)
        return 0;
    size_t count = 0;
    for (ENVGRAPH_CAND *C = envgraph_cands; C != NULL; C = C->next)
    {
        if (C->len != M->len)
            continue;
        if (strcmp(C->resource_key, E->name) != 0)
            continue;
        if (memcmp(C->payload, M->payload, M->len) == 0)
            continue;
        count++;
    }
    return count;
}

static MSG *envgraph_mutate(const ENTRY *E, MSG *M, RNG &R)
{
    size_t count = envgraph_count_matches(E, M);
    if (count == 0)
        return NULL;
    size_t idx = R.rand(0, (uint32_t)count - 1);
    for (ENVGRAPH_CAND *C = envgraph_cands; C != NULL; C = C->next)
    {
        if (C->len != M->len)
            continue;
        if (strcmp(C->resource_key, E->name) != 0)
            continue;
        if (memcmp(C->payload, M->payload, M->len) == 0)
            continue;
        if (idx-- != 0)
            continue;

        MSG *N = clone(M);
        memcpy(N->payload, C->payload, C->len);
        return N;
    }
    return NULL;
}
