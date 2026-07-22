/*
 * Active-recording frontier logging.
 *
 * The fuzzer must not query the real environment from a fuzz leaf.  Instead,
 * unknown boundaries are appended to out/frontiers/frontiers.jsonl for an
 * external campaign runner to turn into new deterministic recordings.
 */

static bool frontier_enabled(void)
{
    if (option_outname == NULL || option_outname[0] == '\0')
        return false;
    return REPLAY;
}

static void frontier_json_string(FILE *stream, const char *str)
{
    fputc('"', stream);
    if (str != NULL)
    {
        for (const unsigned char *p = (const unsigned char *)str; *p != '\0';
            p++)
        {
            switch (*p)
            {
                case '"':  fputs("\\\"", stream); break;
                case '\\': fputs("\\\\", stream); break;
                case '\b': fputs("\\b",  stream); break;
                case '\f': fputs("\\f",  stream); break;
                case '\n': fputs("\\n",  stream); break;
                case '\r': fputs("\\r",  stream); break;
                case '\t': fputs("\\t",  stream); break;
                default:
                    if (*p < 0x20)
                        fprintf(stream, "\\u%.4x", *p);
                    else
                        fputc(*p, stream);
                    break;
            }
        }
    }
    fputc('"', stream);
}

static FILE *frontier_open_log(void)
{
    PRINTER P;
    P.format("%s/frontiers", option_outname);
    if (syscall(SYS_mkdir, P.str(), 0777) < 0 && errno != EEXIST)
    {
        if (option_log >= 3)
            fprintf(stderr, "%sFRONTIER%s failed to mkdir %s: %s\n",
                YELLOW, OFF, P.str(), strerror(errno));
        return NULL;
    }
    P.reset();
    P.format("%s/frontiers/frontiers.jsonl", option_outname);
    int fd = (int)syscall(SYS_open, P.str(),
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0664);
    if (fd < 0)
    {
        if (option_log >= 3)
            fprintf(stderr, "%sFRONTIER%s failed to open %s: %s\n",
                YELLOW, OFF, P.str(), strerror(errno));
        return NULL;
    }
    FILE *stream = fdopen(fd, "a");
    if (stream == NULL)
    {
        if (option_log >= 3)
            fprintf(stderr, "%sFRONTIER%s failed to fdopen %s: %s\n",
                YELLOW, OFF, P.str(), strerror(errno));
        syscall(SYS_close, fd);
        return NULL;
    }
    return stream;
}

static void frontier_write_prefix(FILE *stream)
{
    fprintf(stream,
        "\"trace_prefix\":{\"stage\":%zu,\"execs\":%zu,"
        "\"msg_id\":%d,\"depth\":%d,\"graph\":%zu,\"frontier\":%zu}",
        (FUZZ == NULL? 0: FUZZ->stage),
        (FUZZ == NULL? 0: FUZZ->execs),
        (FUZZ == NULL? -1: FUZZ->id),
        fuzzer_depth,
        (FUZZ == NULL? 0: FUZZ->graphs),
        (FUZZ == NULL? 0: FUZZ->frontiers));
}

static void frontier_write_output_summary(FILE *stream)
{
    if (FUZZ == NULL)
    {
        fputs("\"recent_output\":{\"cov\":0,\"ports\":[]}", stream);
        return;
    }

    fprintf(stream, "\"recent_output\":{\"cov\":%u,\"ports\":[",
        FUZZ->out.cov);
    bool first = true;
    for (int i = 0; i < OUTPUT::NPORTS; i++)
    {
        const WRITE *W = &FUZZ->out.outs[i];
        if (W->port < 0)
            continue;
        if (!first)
            fputc(',', stream);
        first = false;
        fprintf(stream, "{\"port\":%d,\"name\":", W->port);
        frontier_json_string(stream, W->name);
        fprintf(stream, ",\"len\":%zu,\"tail_len\":%zu,\"preview_hex\":\"",
            W->len, W->tail_len);
        size_t n = MIN(W->tail_len, (size_t)32);
        for (size_t j = 0; j < n; j++)
            fprintf(stream, "%.2x", W->tail[j]);
        fputs("\"}", stream);
    }
    fputs("]}", stream);
}

static void frontier_log_queue(const char *source, const ENTRY *E,
    size_t request_len)
{
    if (!frontier_enabled() || E == NULL)
        return;
    FILE *stream = frontier_open_log();
    if (stream == NULL)
        return;

    fputs("{\"type\":\"frontier\",\"kind\":\"queue-empty\",\"source\":",
        stream);
    frontier_json_string(stream, source);
    fprintf(stream, ",\"pid\":%d,\"fd\":%d,\"port\":%d,",
        getpid(), E->fd, E->port);
    fputs("\"resource_key\":", stream);
    frontier_json_string(stream, E->name);
    fprintf(stream,
        ",\"request_shape\":{\"operation\":\"read\",\"max_len\":%zu,"
        "\"filetype\":%u,\"socktype\":%d},",
        request_len, E->filetype, E->socktype);
    frontier_write_prefix(stream);
    fputc(',', stream);
    frontier_write_output_summary(stream);
    fputs("}\n", stream);
    fclose(stream);
}

static const char *frontier_syscall_path(const SYSCALL *call)
{
    switch (call->no)
    {
        case SYS_open:
        case SYS_stat:
        case SYS_lstat:
        case SYS_access:
            return call->arg0.path;
        case SYS_openat:
            return call->arg1.path;
        default:
            return NULL;
    }
}

static void frontier_log_syscall(const char *reason, const SYSCALL *call,
    intptr_t result)
{
    if (!frontier_enabled() || call == NULL)
        return;
    FILE *stream = frontier_open_log();
    if (stream == NULL)
        return;

    fputs("{\"type\":\"frontier\",\"kind\":\"syscall-miss\",\"reason\":",
        stream);
    frontier_json_string(stream, reason);
    fprintf(stream,
        ",\"pid\":%d,\"syscall_no\":%d,\"syscall_name\":",
        getpid(), call->no);
    frontier_json_string(stream, syscall_name(call->no));
    fprintf(stream, ",\"result\":%ld", (long)result);
    const char *path = frontier_syscall_path(call);
    if (path != NULL)
    {
        fputs(",\"resource_key\":", stream);
        frontier_json_string(stream, path);
    }
    fprintf(stream,
        ",\"request_shape\":{\"arg0\":%ld,\"arg1\":%ld,\"arg2\":%ld},",
        (long)call->arg0.val, (long)call->arg1.val, (long)call->arg2.val);
    frontier_write_prefix(stream);
    fputc(',', stream);
    frontier_write_output_summary(stream);
    fputs("}\n", stream);
    fclose(stream);
}
