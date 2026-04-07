/*
THIS PARSER IS VULNERABLE IN PROFILE PARSING (OVERFLOW)
SEE FUZZER_SAMPLES
*/

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_SIZE 4096

struct png_state {
    uint32_t width;
    uint32_t height;
    int saw_ihdr;
    unsigned metadata_chunks;
};

struct preview_frame {
    char preview[64];
    void (*emit)(const char *text);
};

static uint32_t read_be32(const uint8_t *ptr) {
    return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
           ((uint32_t)ptr[2] << 8) | (uint32_t)ptr[3];
}

static void parser_log(const char *message) {
    fprintf(stderr, "[png-ex01] %s\n", message);
}

static void parser_logf(const char *fmt, const char *value) {
    fprintf(stderr, "[png-ex01] ");
    fprintf(stderr, fmt, value);
    fputc('\n', stderr);
}

static void parser_log_chunk(const uint8_t *chunk_type, uint32_t chunk_len) {
    fprintf(stderr, "[png-ex01] chunk type=%c%c%c%c len=%u\n", chunk_type[0],
            chunk_type[1], chunk_type[2], chunk_type[3], chunk_len);
}

static size_t read_file_all(const char *path, uint8_t *buffer, size_t capacity) {
    FILE *fp = NULL;
    size_t used = 0;
    size_t got = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[png-ex01] failed to open %s: %s\n", path, strerror(errno));
        return 0;
    }

    while (used < capacity) {
        got = fread(buffer + used, 1, capacity - used, fp);
        used += got;
        if (got == 0) {
            break;
        }
    }

    if (ferror(fp) != 0) {
        fprintf(stderr, "[png-ex01] read error on %s\n", path);
        fclose(fp);
        return 0;
    }

    if (used == capacity && fgetc(fp) != EOF) {
        fprintf(stderr, "[png-ex01] input truncated at %zu bytes\n", capacity);
    }

    fclose(fp);
    return used;
}

static size_t find_nul(const uint8_t *buffer, size_t len) {
    for (size_t index = 0; index < len; index++) {
        if (buffer[index] == 0) {
            return index;
        }
    }

    return (size_t)-1;
}

static void record_profile(const char *text) {
    volatile unsigned checksum = 0;

    for (size_t index = 0; text[index] != '\0' && index < 24; index++) {
        checksum ^= (unsigned char)text[index];
    }

    if (checksum == 0xFFFFu) {
        puts(text);
    }
}

static int parse_profile_header(const uint8_t *text, size_t text_len,
                                unsigned *declared_len,
                                size_t *payload_offset) {
    static const char prefix[] = "Profile:";
    size_t cursor = sizeof(prefix) - 1;
    unsigned value = 0;
    size_t digit_count = 0;

    if (text_len <= cursor || memcmp(text, prefix, cursor) != 0) {
        return 0;
    }

    while (cursor < text_len && digit_count < 4 && isdigit(text[cursor]) != 0) {
        value = (value * 10u) + (unsigned)(text[cursor] - '0');
        cursor++;
        digit_count++;
    }

    if (digit_count < 2 || cursor >= text_len || text[cursor] != ':') {
        return 0;
    }

    cursor++;
    if (value < 24u || cursor >= text_len) {
        return 0;
    }

    *declared_len = value;
    *payload_offset = cursor;
    fprintf(stderr, "[png-ex01] profile header accepted declared_len=%u payload_offset=%zu\n",
            value, cursor);
    return 1;
}

static int parse_ihdr(const uint8_t *chunk_data, size_t chunk_len,
                      struct png_state *state) {
    if (chunk_len != 13) {
        return 0;
    }

    state->width = read_be32(chunk_data);
    state->height = read_be32(chunk_data + 4);
    state->saw_ihdr = (state->width != 0 && state->height != 0);
    fprintf(stderr, "[png-ex01] IHDR width=%u height=%u valid=%d\n", state->width,
            state->height, state->saw_ihdr);
    return state->saw_ihdr;
}

static int parse_itxt_chunk(const uint8_t *chunk_data, size_t chunk_len,
                            struct png_state *state) {
    unsigned declared_len = 0;
    size_t payload_offset = 0;
    size_t keyword_len = 0;
    size_t cursor = 0;
    size_t lang_len = 0;
    size_t translated_len = 0;
    size_t text_len = 0;
    size_t header_copy = 0;
    const uint8_t *text = NULL;
    const uint8_t *payload = NULL;
    struct preview_frame frame;

    if (!state->saw_ihdr || state->width < 16 || state->height < 16 ||
        chunk_len < 40) {
        parser_log("iTXt skipped because image state is too small or IHDR is missing");
        return 0;
    }

    keyword_len = find_nul(chunk_data, chunk_len);
    if (keyword_len == (size_t)-1 || keyword_len < 8 || keyword_len > 31) {
        parser_log("iTXt rejected because keyword field is malformed");
        return 0;
    }

    cursor = keyword_len + 1;
    if (cursor + 2 >= chunk_len) {
        parser_log("iTXt rejected because compression fields are truncated");
        return 0;
    }

    if (chunk_data[cursor] != 0 || chunk_data[cursor + 1] != 0) {
        parser_log("iTXt rejected because compressed text is unsupported");
        return 0;
    }
    cursor += 2;

    lang_len = find_nul(chunk_data + cursor, chunk_len - cursor);
    if (lang_len == (size_t)-1 || lang_len > 8) {
        parser_log("iTXt rejected because language tag is malformed");
        return 0;
    }
    cursor += lang_len + 1;

    translated_len = find_nul(chunk_data + cursor, chunk_len - cursor);
    if (translated_len == (size_t)-1 || translated_len > 16) {
        parser_log("iTXt rejected because translated keyword is malformed");
        return 0;
    }
    cursor += translated_len + 1;

    if (cursor >= chunk_len) {
        parser_log("iTXt rejected because text payload is empty");
        return 0;
    }

    if (memcmp(chunk_data, "Raw profile type exif", 21) != 0 &&
        memcmp(chunk_data, "XML:com.adobe.xmp", 17) != 0) {
        parser_log("iTXt keyword ignored because it is not an ExifTool-style profile");
        return 0;
    }

    fprintf(stderr, "[png-ex01] iTXt candidate keyword_len=%zu lang_len=%zu translated_len=%zu\n",
            keyword_len, lang_len, translated_len);

    text = chunk_data + cursor;
    text_len = chunk_len - cursor;
    if (!parse_profile_header(text, text_len, &declared_len, &payload_offset)) {
        parser_log("profile header rejected");
        return 0;
    }

    payload = text + payload_offset;
    if ((size_t)declared_len > text_len - payload_offset) {
        parser_log("profile payload rejected because declared length exceeds chunk body");
        return 0;
    }

    memset(&frame, 0, sizeof(frame));
    frame.emit = record_profile;

    header_copy = keyword_len;
    if (header_copy > 15) {
        header_copy = 15;
    }

    fprintf(stderr,
            "[png-ex01] vulnerable preview copy header_copy=%zu declared_len=%u preview_size=%zu\n",
            header_copy, declared_len, sizeof(frame.preview));
    memcpy(frame.preview, chunk_data, header_copy);
    frame.preview[header_copy] = ':';
    memcpy(frame.preview + header_copy + 1, payload, declared_len);
    frame.preview[header_copy + 1 + declared_len] = '\0';
    frame.emit(frame.preview);

    state->metadata_chunks++;
    return 1;
}

static void scan_png(const uint8_t *buffer, size_t size) {
    static const uint8_t png_magic[8] = {0x89, 'P', 'N', 'G',
                                         '\r', '\n', 0x1a, '\n'};
    struct png_state state = {0};
    size_t cursor = 8;

    if (size < sizeof(png_magic) || memcmp(buffer, png_magic, sizeof(png_magic)) != 0) {
        parser_log("input rejected because PNG signature is invalid");
        return;
    }

    fprintf(stderr, "[png-ex01] scanning png size=%zu\n", size);

    while (cursor + 12 <= size) {
        uint32_t chunk_len = read_be32(buffer + cursor);
        const uint8_t *chunk_type = buffer + cursor + 4;
        const uint8_t *chunk_data = buffer + cursor + 8;

        parser_log_chunk(chunk_type, chunk_len);
        cursor += 8;
        if (cursor + (size_t)chunk_len + 4 > size) {
            parser_log("chunk rejected because its declared length escapes the file");
            return;
        }

        if (memcmp(chunk_type, "IHDR", 4) == 0) {
            if (!parse_ihdr(chunk_data, chunk_len, &state)) {
                parser_log("IHDR rejected");
                return;
            }
        } else if (memcmp(chunk_type, "iTXt", 4) == 0) {
            parse_itxt_chunk(chunk_data, chunk_len, &state);
        } else if (memcmp(chunk_type, "IEND", 4) == 0) {
            fprintf(stderr, "[png-ex01] finished image metadata_chunks=%u\n",
                    state.metadata_chunks);
            return;
        }

        cursor += (size_t)chunk_len + 4;
    }

    parser_log("scan finished without IEND");
}

int main(int argc, char **argv) {
    uint8_t buffer[MAX_INPUT_SIZE];
    size_t size = 0;

    if (argc < 2) {
        parser_log("usage: target_png_parser <png-path>");
        return 1;
    }

    parser_logf("opening png path=%s", argv[1]);
    size = read_file_all(argv[1], buffer, sizeof(buffer));
    fprintf(stderr, "[png-ex01] bytes_read=%zu\n", size);

    scan_png(buffer, size);
    return 0;
}
