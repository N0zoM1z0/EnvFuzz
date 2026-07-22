/*
 * EnvGraph runtime candidate support.
 *
 * M1 uses graph data for concrete inbound payload replacement.  M2 extends
 * that to empty-queue frontier payloads.  M3 imports a small whitelist of
 * recorded schedule nodes into the existing syscall emulation lookup table.
 * M5 adds sequence-aware queue frontiers for TTY-like byte streams.
 * M6 adds output-context-aware TTY action frontiers.
 */

static void emulate_set_syscall(const SYSCALL *call);

struct ENVGRAPH_CAND
{
    ENVGRAPH_CAND *next;
    const char *resource_key;
    size_t len;
    uint8_t *payload;
};

struct ENVGRAPH_SEQ
{
    ENVGRAPH_SEQ *next;
    const char *resource_key;
    size_t len;
    uint8_t *payload;
};

struct ENVGRAPH_ACTION
{
    ENVGRAPH_ACTION *next;
    const char *resource_key;
    const char *context_key;
    const char *state_key;
    uint8_t context_mode;
    size_t context_len;
    uint8_t *context;
    size_t len;
    uint8_t *payload;
};

enum
{
    ENVGRAPH_CONTEXT_SUBSTRING = 0,
    ENVGRAPH_CONTEXT_STATE     = 1,
    ENVGRAPH_CONTEXT_BOTH      = 2,
};

static ENVGRAPH_CAND *envgraph_cands = NULL;
static ENVGRAPH_SEQ *envgraph_seqs = NULL;
static ENVGRAPH_ACTION *envgraph_actions = NULL;
static ENVGRAPH_SEQ *envgraph_active_seq = NULL;
static ENVGRAPH_ACTION *envgraph_active_action = NULL;
static size_t envgraph_cand_count = 0;
static size_t envgraph_seq_count = 0;
static size_t envgraph_action_count = 0;
static size_t envgraph_sched_count = 0;
static size_t envgraph_active_seq_off = 0;
static size_t envgraph_active_action_off = 0;
static size_t envgraph_action_uses = 0;
static bool envgraph_frontier_more = false;

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

static void envgraph_add_sequence(const char *resource_key, size_t len,
    uint8_t *payload)
{
    ENVGRAPH_SEQ *S = (ENVGRAPH_SEQ *)xmalloc(sizeof(*S));
    S->resource_key = resource_key;
    S->len          = len;
    S->payload      = payload;
    S->next         = envgraph_seqs;
    envgraph_seqs   = S;
    envgraph_seq_count++;
}

static uint8_t envgraph_parse_context_mode(const char *mode)
{
    if (mode == NULL || strcmp(mode, "substring") == 0)
        return ENVGRAPH_CONTEXT_SUBSTRING;
    if (strcmp(mode, "state") == 0)
        return ENVGRAPH_CONTEXT_STATE;
    if (strcmp(mode, "both") == 0)
        return ENVGRAPH_CONTEXT_BOTH;
    return ENVGRAPH_CONTEXT_SUBSTRING;
}

static void envgraph_add_action(const char *resource_key,
    const char *context_key, const char *state_key, uint8_t context_mode,
    size_t context_len, uint8_t *context, size_t len, uint8_t *payload)
{
    ENVGRAPH_ACTION *A = (ENVGRAPH_ACTION *)xmalloc(sizeof(*A));
    A->resource_key = resource_key;
    A->context_key  = context_key;
    A->state_key    = state_key;
    A->context_mode = context_mode;
    A->context_len  = context_len;
    A->context      = context;
    A->len          = len;
    A->payload      = payload;
    A->next         = envgraph_actions;
    envgraph_actions = A;
    envgraph_action_count++;
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
    while ((p = envgraph_find_literal(p, end, "\"sequence_hex\"")) != NULL)
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
        char *sequence_hex = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "sequence_hex"), obj_end);
        size_t len = 0;
        bool ok_len = envgraph_parse_size(
            envgraph_find_key(obj, obj_end, "sequence_len"), obj_end, &len);

        if (resource_key == NULL || sequence_hex == NULL || !ok_len)
            error("invalid EnvGraph \"%s\": malformed sequence candidate",
                option_graphname);

        if (len > 0)
        {
            uint8_t *payload = envgraph_decode_hex(sequence_hex, len);
            if (payload != NULL)
                envgraph_add_sequence(resource_key, len, payload);
            else
                error("invalid EnvGraph \"%s\": malformed sequence_hex",
                    option_graphname);
        }
        else
            xfree(resource_key);
        if (sequence_hex != NULL)
            xfree(sequence_hex);

        p = obj_end + 1;
    }

    p = buf;
    while ((p = envgraph_find_literal(p, end, "\"action_hex\"")) != NULL)
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
        char *context_key = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "context_resource_key"),
            obj_end);
        char *state_key = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "state_key"), obj_end);
        char *context_mode = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "context_mode"), obj_end);
        char *action_hex = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "action_hex"), obj_end);
        char *context_hex = envgraph_parse_string(
            envgraph_find_key(obj, obj_end, "context_hex"), obj_end);
        size_t action_len = 0, context_len = 0;
        bool ok_action_len = envgraph_parse_size(
            envgraph_find_key(obj, obj_end, "action_len"), obj_end,
            &action_len);
        bool ok_context_len = envgraph_parse_size(
            envgraph_find_key(obj, obj_end, "context_len"), obj_end,
            &context_len);

        if (resource_key == NULL || context_key == NULL ||
                action_hex == NULL || context_hex == NULL ||
                !ok_action_len || !ok_context_len)
            error("invalid EnvGraph \"%s\": malformed TTY action candidate",
                option_graphname);

        if (action_len > 0 && context_len > 0)
        {
            uint8_t *action = envgraph_decode_hex(action_hex, action_len);
            uint8_t *context = envgraph_decode_hex(context_hex, context_len);
            if (action == NULL || context == NULL)
                error("invalid EnvGraph \"%s\": malformed TTY action hex",
                    option_graphname);
            envgraph_add_action(resource_key, context_key, state_key,
                envgraph_parse_context_mode(context_mode), context_len,
                context, action_len, action);
        }
        else
        {
            xfree(resource_key);
            xfree(context_key);
            if (state_key != NULL)
                xfree(state_key);
        }
        if (context_mode != NULL)
            xfree(context_mode);
        if (action_hex != NULL)
            xfree(action_hex);
        if (context_hex != NULL)
            xfree(context_hex);

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
        fprintf(stderr,
            "%sENVGRAPH%s %s candidates=%zu sequences=%zu actions=%zu "
            "schedules=%zu\n",
            MAGENTA, OFF, option_graphname, envgraph_cand_count,
            envgraph_seq_count, envgraph_action_count, envgraph_sched_count);
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

static MSG *envgraph_make_frontier_msg(const ENTRY *E, const uint8_t *payload,
    size_t len, uint32_t id)
{
    MSG *M = (MSG *)pmalloc(sizeof(MSG) + len);
    M->next     = M->prev = M;
    M->port     = E->port;
    M->error    = 0;
    M->outbound = false;
    M->id       = id;
    M->len      = len;
    memcpy(M->payload, payload, len);
    return M;
}

static size_t envgraph_normalize_tty(const uint8_t *data, size_t len,
    uint8_t *out, size_t out_size)
{
    size_t j = 0;
    int esc = 0;
    bool last_space = false;
    for (size_t i = 0; i < len; i++)
    {
        uint8_t x = data[i];
        if (esc == 1)
        {
            if (x == '[')
                esc = 2;
            else if (x == '(' || x == ')' || x == '*' || x == '+' ||
                    x == '-' || x == '.' || x == '/')
                esc = 3;
            else
                esc = 0;
            continue;
        }
        if (esc == 2)
        {
            if (x >= 0x40 && x <= 0x7E)
                esc = 0;
            continue;
        }
        if (esc == 3)
        {
            esc = 0;
            continue;
        }
        if (x == 0x1B)
        {
            esc = 1;
            continue;
        }
        if (x == '\t' || x == '\n' || x == '\r' || x < 0x20 ||
                x == 0x7F || x >= 0x7F)
        {
            if (!last_space && j > 0 && j < out_size)
            {
                out[j++] = ' ';
                last_space = true;
            }
            continue;
        }
        if (j >= out_size)
            break;
        out[j++] = x;
        last_space = (x == ' ');
    }
    while (j > 0 && out[j-1] == ' ')
        j--;
    return j;
}

static bool envgraph_contains(const uint8_t *haystack, size_t haystack_len,
    const uint8_t *needle, size_t needle_len)
{
    if (needle_len == 0)
        return true;
    if (haystack_len < needle_len)
        return false;
    for (size_t i = 0; i + needle_len <= haystack_len; i++)
    {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return true;
    }
    return false;
}

static bool envgraph_contains_str(const uint8_t *haystack, size_t haystack_len,
    const char *needle)
{
    return envgraph_contains(haystack, haystack_len,
        (const uint8_t *)needle, strlen(needle));
}

static const char *envgraph_tty_state(const uint8_t *context,
    size_t context_len)
{
    if (envgraph_contains_str(context, context_len, "Search:"))
        return "prompt:search";
    if (envgraph_contains_str(context, context_len, "Write to File:") ||
            envgraph_contains_str(context, context_len,
                "File Name to Write"))
        return "prompt:write";
    if (envgraph_contains_str(context, context_len, "Save modified") ||
            envgraph_contains_str(context, context_len, "Save file"))
        return "prompt:save";
    if (context_len > 0)
        return "edit";
    return "unknown";
}

static bool envgraph_output_matches(const ENVGRAPH_ACTION *A,
    const OUTPUT *out)
{
    if (A == NULL || out == NULL || A->context_len == 0)
        return false;
    for (int i = 0; i < OUTPUT::NPORTS; i++)
    {
        const WRITE *W = &out->outs[i];
        if (W->port < 0)
            continue;
        if (A->context_key != NULL && strcmp(A->context_key, W->name) != 0)
            continue;
        const uint8_t *data = (W->tail_len > 0? W->tail: W->data);
        size_t len = (W->tail_len > 0? W->tail_len: W->len);
        uint8_t norm[WRITE::WINDOW];
        size_t norm_len = envgraph_normalize_tty(data, len, norm,
            sizeof(norm));
        bool state_match = A->state_key != NULL &&
            strcmp(A->state_key, envgraph_tty_state(norm, norm_len)) == 0;
        bool context_match = envgraph_contains(norm, norm_len, A->context,
            A->context_len);
        switch (A->context_mode)
        {
            case ENVGRAPH_CONTEXT_STATE:
                if (state_match)
                    return true;
                break;
            case ENVGRAPH_CONTEXT_BOTH:
                if (state_match && context_match)
                    return true;
                break;
            default:
                if (context_match)
                    return true;
                break;
        }
    }
    return false;
}

static size_t envgraph_count_action_matches(const ENTRY *E, const OUTPUT *out)
{
    if (!envgraph_enabled() || E == NULL || E->name == NULL)
        return 0;
    size_t count = 0;
    for (ENVGRAPH_ACTION *A = envgraph_actions; A != NULL; A = A->next)
    {
        if (A->len == 0)
            continue;
        if (strcmp(A->resource_key, E->name) != 0)
            continue;
        if (!envgraph_output_matches(A, out))
            continue;
        count++;
    }
    return count;
}

static size_t envgraph_count_sequence_matches(const ENTRY *E)
{
    if (!envgraph_enabled() || E == NULL || E->name == NULL)
        return 0;
    size_t count = 0;
    for (ENVGRAPH_SEQ *S = envgraph_seqs; S != NULL; S = S->next)
    {
        if (S->len == 0)
            continue;
        if (strcmp(S->resource_key, E->name) != 0)
            continue;
        count++;
    }
    return count;
}

static bool envgraph_has_action_frontier(const ENTRY *E, const OUTPUT *out)
{
    if (E == NULL || E->name == NULL)
        return false;
    if (envgraph_active_action != NULL &&
            envgraph_active_action_off < envgraph_active_action->len &&
            strcmp(envgraph_active_action->resource_key, E->name) == 0)
        return true;
    return envgraph_count_action_matches(E, out) > 0;
}

static bool envgraph_has_frontier(const ENTRY *E, const OUTPUT *out)
{
    return envgraph_has_action_frontier(E, out) ||
        envgraph_count_frontier_matches(E, SIZE_MAX) > 0 ||
        envgraph_count_sequence_matches(E) > 0;
}

static ENVGRAPH_ACTION *envgraph_choose_action(const ENTRY *E,
    const OUTPUT *out, RNG &R)
{
    size_t count = envgraph_count_action_matches(E, out);
    if (count == 0)
        return NULL;
    size_t idx = R.rand(0, (uint32_t)count - 1);
    for (ENVGRAPH_ACTION *A = envgraph_actions; A != NULL; A = A->next)
    {
        if (A->len == 0)
            continue;
        if (strcmp(A->resource_key, E->name) != 0)
            continue;
        if (!envgraph_output_matches(A, out))
            continue;
        if (idx-- != 0)
            continue;
        return A;
    }
    return NULL;
}

static MSG *envgraph_action_frontier(const ENTRY *E, size_t max_len,
    uint32_t id, const OUTPUT *out, RNG &R)
{
    if (!envgraph_enabled() || E == NULL || E->name == NULL || max_len == 0)
        return NULL;

    if (envgraph_active_action == NULL ||
            envgraph_active_action_off >= envgraph_active_action->len ||
            strcmp(envgraph_active_action->resource_key, E->name) != 0)
    {
        if (envgraph_action_uses >= 1)
            return NULL;
        envgraph_active_action = envgraph_choose_action(E, out, R);
        envgraph_active_action_off = 0;
        if (envgraph_active_action != NULL)
            envgraph_action_uses++;
    }
    if (envgraph_active_action == NULL)
        return NULL;

    size_t remaining = envgraph_active_action->len - envgraph_active_action_off;
    size_t len = (remaining < max_len? remaining: max_len);
    if (len == 0)
        return NULL;

    MSG *M = envgraph_make_frontier_msg(E,
        envgraph_active_action->payload + envgraph_active_action_off, len, id);
    envgraph_active_action_off += len;
    if (envgraph_active_action_off >= envgraph_active_action->len)
    {
        envgraph_active_action = NULL;
        envgraph_active_action_off = 0;
    }
    else
        envgraph_frontier_more = true;
    return M;
}

static ENVGRAPH_SEQ *envgraph_choose_sequence(const ENTRY *E, RNG &R)
{
    size_t count = envgraph_count_sequence_matches(E);
    if (count == 0)
        return NULL;
    size_t idx = R.rand(0, (uint32_t)count - 1);
    for (ENVGRAPH_SEQ *S = envgraph_seqs; S != NULL; S = S->next)
    {
        if (S->len == 0)
            continue;
        if (strcmp(S->resource_key, E->name) != 0)
            continue;
        if (idx-- != 0)
            continue;
        return S;
    }
    return NULL;
}

static MSG *envgraph_sequence_frontier(const ENTRY *E, size_t max_len,
    uint32_t id, RNG &R)
{
    if (!envgraph_enabled() || E == NULL || E->name == NULL || max_len == 0)
        return NULL;

    if (envgraph_active_seq == NULL ||
            envgraph_active_seq_off >= envgraph_active_seq->len ||
            strcmp(envgraph_active_seq->resource_key, E->name) != 0)
    {
        envgraph_active_seq = envgraph_choose_sequence(E, R);
        envgraph_active_seq_off = 0;
    }
    if (envgraph_active_seq == NULL)
        return NULL;

    size_t remaining = envgraph_active_seq->len - envgraph_active_seq_off;
    size_t len = (remaining < max_len? remaining: max_len);
    if (len == 0)
        return NULL;

    MSG *M = envgraph_make_frontier_msg(E,
        envgraph_active_seq->payload + envgraph_active_seq_off, len, id);
    envgraph_active_seq_off += len;
    if (envgraph_active_seq_off >= envgraph_active_seq->len)
    {
        envgraph_active_seq = NULL;
        envgraph_active_seq_off = 0;
    }
    else
        envgraph_frontier_more = true;
    return M;
}

static MSG *envgraph_payload_frontier(const ENTRY *E, size_t max_len,
    uint32_t id, RNG &R)
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

        return envgraph_make_frontier_msg(E, C->payload, C->len, id);
    }
    return NULL;
}

static MSG *envgraph_frontier(const ENTRY *E, size_t max_len, uint32_t id,
    RNG &R, const OUTPUT *out)
{
    envgraph_frontier_more = false;
    MSG *M = envgraph_action_frontier(E, max_len, id, out, R);
    if (M != NULL)
        return M;
    M = envgraph_sequence_frontier(E, max_len, id, R);
    if (M != NULL)
        return M;
    return envgraph_payload_frontier(E, max_len, id, R);
}

static bool envgraph_frontier_keeps_queue_open(void)
{
    return envgraph_frontier_more;
}
