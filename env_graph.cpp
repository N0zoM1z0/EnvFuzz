/*
 * EnvGraph runtime candidate support.
 *
 * M1 uses graph data for concrete inbound payload replacement.  M2 extends
 * that to empty-queue frontier payloads.  M3 imports a small whitelist of
 * recorded schedule nodes into the existing syscall emulation lookup table.
 */

static void emulate_set_syscall(const SYSCALL *call);

struct ENVGRAPH_CAND
{
    ENVGRAPH_CAND *next;
    const char *resource_key;
    size_t len;
    uint8_t *payload;
};

static ENVGRAPH_CAND *envgraph_cands = NULL;
static size_t envgraph_cand_count = 0;
static size_t envgraph_sched_count = 0;

static bool envgraph_enabled(void)
{
    return option_graphname != NULL && option_graphname[0] != '\0';
}

static const char *envgraph_skip_ws(const char *p, const char *end)
{
    if (p == NULL)
        return NULL;
    while (p < end && isspace(*p))
        p++;
    return p;
}

static const char *envgraph_find_key(const char *start, const char *end,
    const char *key)
{
    if (start == NULL)
        return NULL;
    PRINTER K;
    K.format("\"%s\"", key);
    size_t klen = strlen(K.str());
    for (const char *p = start; p + klen <= end; p++)
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
    if (p == NULL)
        return false;
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

static bool envgraph_schedule_allowed(int no)
{
    switch (no)
    {
        case SYS_open: case SYS_openat:
        case SYS_stat: case SYS_lstat:
        case SYS_access:
            return true;
        default:
            return false;
    }
}

static bool envgraph_schedule_valid(const uint8_t *payload, size_t len)
{
    if (payload == NULL || len < sizeof(SYSCALL) + sizeof(AUX))
        return false;
    const SYSCALL *call = (const SYSCALL *)payload;
    if (!envgraph_schedule_allowed(call->no) || call->result < 0)
        return false;
    const AUX *aux = call->aux;
    size_t off = sizeof(SYSCALL);
    while (off + sizeof(AUX) <= len)
    {
        const AUX *A = (const AUX *)(payload + off);
        off += sizeof(AUX);
        if (off + A->size > len)
            return false;
        off += A->size;
        if (A->kind == AEND)
            return off == len;
        aux = (const AUX *)(payload + off);
    }
    (void)aux;
    return false;
}

static void envgraph_import_schedule(uint8_t *payload, size_t len)
{
    if (!envgraph_schedule_valid(payload, len))
    {
        xfree(payload);
        return;
    }

    SYSCALL *call = (SYSCALL *)payload;
    call->replay = false;
    const AUX *aux = call->aux;
    const char *name;
    int port;
    if ((name = aux_str(aux, MR_, ANAM)) != NULL &&
            (port = aux_int(aux, MR_, APRT)) > 0)
        name_set(port, name, /*replace=*/true);
    if ((name = aux_str(aux, M_R, ANAM)) != NULL &&
            (port = aux_int(aux, M_R, APRT)) > 0)
        name_set(port, name, /*replace=*/true);

    emulate_set_syscall(call);
    envgraph_sched_count++;
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
    char *format = envgraph_parse_string(
        envgraph_find_key(buf, end, "format"), end);
    if (format == NULL || strcmp(format, "envgraph-v0") != 0)
        error("invalid EnvGraph \"%s\": missing format envgraph-v0",
            option_graphname);
    xfree(format);

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

        if (resource_key == NULL || payload_hex == NULL || !ok_len)
            error("invalid EnvGraph \"%s\": malformed payload candidate",
                option_graphname);

        if (len > 0)
        {
            uint8_t *payload = envgraph_decode_hex(payload_hex, len);
            if (payload != NULL)
                envgraph_add(resource_key, len, payload);
            else
                error("invalid EnvGraph \"%s\": malformed payload_hex",
                    option_graphname);
        }
        else
            xfree(resource_key);
        if (payload_hex != NULL)
            xfree(payload_hex);

        p = obj_end + 1;
    }

    p = buf;
    while ((p = envgraph_find_literal(p, end, "\"sched_hex\"")) != NULL)
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

        char *sched_hex = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "sched_hex"), obj_end);
        size_t len = 0;
        bool ok_len = envgraph_parse_size(
            envgraph_find_key(obj, obj_end, "sched_len"), obj_end, &len);
        if (sched_hex == NULL || !ok_len)
            error("invalid EnvGraph \"%s\": malformed schedule candidate",
                option_graphname);

        if (len > 0)
        {
            uint8_t *payload = envgraph_decode_hex(sched_hex, len);
            if (payload != NULL)
                envgraph_import_schedule(payload, len);
            else
                error("invalid EnvGraph \"%s\": malformed sched_hex",
                    option_graphname);
        }
        if (sched_hex != NULL)
            xfree(sched_hex);

        p = obj_end + 1;
    }

    xfree(buf);
    if (option_log >= 1)
        fprintf(stderr, "%sENVGRAPH%s %s candidates=%zu schedules=%zu\n",
            MAGENTA, OFF, option_graphname, envgraph_cand_count,
            envgraph_sched_count);
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

static size_t envgraph_count_frontier_matches(const ENTRY *E, size_t max_len)
{
    if (!envgraph_enabled() || E == NULL || E->name == NULL || max_len == 0)
        return 0;
    size_t count = 0;
    for (ENVGRAPH_CAND *C = envgraph_cands; C != NULL; C = C->next)
    {
        if (C->len == 0 || C->len > max_len)
            continue;
        if (strcmp(C->resource_key, E->name) != 0)
            continue;
        count++;
    }
    return count;
}

static bool envgraph_has_frontier(const ENTRY *E)
{
    return envgraph_count_frontier_matches(E, SIZE_MAX) > 0;
}

static MSG *envgraph_frontier(const ENTRY *E, size_t max_len, uint32_t id,
    RNG &R)
{
    size_t count = envgraph_count_frontier_matches(E, max_len);
    if (count == 0)
        return NULL;
    size_t idx = R.rand(0, (uint32_t)count - 1);
    for (ENVGRAPH_CAND *C = envgraph_cands; C != NULL; C = C->next)
    {
        if (C->len == 0 || C->len > max_len)
            continue;
        if (strcmp(C->resource_key, E->name) != 0)
            continue;
        if (idx-- != 0)
            continue;

        MSG *M = (MSG *)pmalloc(sizeof(MSG) + C->len);
        M->next     = M->prev = M;
        M->port     = E->port;
        M->error    = 0;
        M->outbound = false;
        M->id       = id;
        M->len      = C->len;
        memcpy(M->payload, C->payload, C->len);
        return M;
    }
    return NULL;
}
