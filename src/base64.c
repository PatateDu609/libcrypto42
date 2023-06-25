#include "common.h"
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define BASE64_CHAR_SET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define BASE64_CHAR_PADDING '='

char *base64_encode(const uint8_t *bytes, size_t len) {
	char  *set  = BASE64_CHAR_SET;
	size_t flen = (size_t) ceil((double) len / 3.) * 4;
	char  *res  = malloc((flen + 1) * sizeof *res);

	size_t j    = 0;
	for (size_t i = 0; i < len; i += 3) {
		uint8_t index = (bytes[i] & 0b11111100) >> 2;
		res[j++]      = set[index];

		if (i + 1 == len) {
			res[j++] = set[(bytes[i] & 0b00000011) << 4];
			break;
		}
		index    = ((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4);
		res[j++] = set[index];

		if (i + 2 == len) {
			res[j++] = set[(bytes[i + 1] & 0b00001111) << 2];
			break;
		}
		index    = ((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6);
		res[j++] = set[index];

		index    = bytes[i + 2] & 0b00111111;
		res[j++] = set[index];
	}
	for (; j < flen; j++) res[j] = BASE64_CHAR_PADDING;
	res[flen] = '\0';
	return res;
}

uint8_t *base64_decode(const char *str, size_t *flen) {
	size_t len     = strlen(str);
	size_t padding = 0;

	// Count padding and check if the string is valid in the same time.
	for (size_t i = 0; i < len; i++) {
		if (str[i] == BASE64_CHAR_PADDING)
			padding++;
		else if (strchr(BASE64_CHAR_SET, str[i]) == NULL || padding)// Invalid character or padding in the middle.
			return NULL;
	}
	if (padding > 2)// Invalid padding.
		return NULL;
	*flen        = (len / 4) * 3 - padding;

	// It is a raw array not a string. \0 can be part of the array and should not be used as a terminator
	uint8_t *res = malloc(*flen * sizeof *res);
	size_t   j   = 0;
	for (size_t i = 0; i < len - padding; i += 4) {
		uint8_t indices[4] = { strchr(BASE64_CHAR_SET, str[i]) - BASE64_CHAR_SET,
			                   strchr(BASE64_CHAR_SET, str[i + 1]) - BASE64_CHAR_SET,
			                   strchr(BASE64_CHAR_SET, str[i + 2]) - BASE64_CHAR_SET,
			                   strchr(BASE64_CHAR_SET, str[i + 3]) - BASE64_CHAR_SET };
		res[j++]           = (indices[0] << 2) | (indices[1] >> 4);
		if (i + 2 == len - padding)
			break;
		res[j++] = ((indices[1] & 0b00001111) << 4) | (indices[2] >> 2);
		if (i + 3 == len - padding)
			break;
		res[j++] = ((indices[2] & 0b00000011) << 6) | indices[3];
	}
	return res;
}

// Base64 stream management

struct stream_ctx {
	uint8_t buf[48];
	size_t  pos;
	uint8_t ref;///< May be the line position if the ctx is in encoder mode, or how much there is
				///< to copy in the buffer if the ctx is in decryption mode
};

// Static globals are initialized to 0
static struct stream_ctx encoder;
static struct stream_ctx decoder;

void                     stream_base64_enc(FILE *out, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        encoder.buf[encoder.pos++] = buf[i];
        if (encoder.pos >= sizeof encoder.buf)// Buffer full -> flush
            stream_base64_enc_flush(out);
    }
}

void stream_base64_enc_flush(FILE *out) {
	if (encoder.pos == 0)
		return;

	char *encoded       = base64_encode(encoder.buf, encoder.pos);
	encoder.pos         = 0;

	size_t len          = strlen(encoded);
	size_t before_break = 64 - encoder.ref;
	encoder.ref += len;

	if (len < before_break)
		fwrite(encoded, 1, len, out);
	else {
		fwrite(encoded, 1, before_break, out);
		fwrite("\n", 1, 1, out);
		fwrite(encoded + before_break, 1, len - before_break, out);
		encoder.ref %= 64;// line length
	}
}

/**
 * @brief Removes new lines and spaces from decoder buffer
 *
 * @param in Input stream to compensate the lost character if any...
 * @param __buf The buffer to sanitize
 * @param len Length of the buffer
 *
 * @return The new len (it may be the same as the old one, but if EOF is reached we won't be able to read again...)
 */
static size_t stream_sanitize_buffer(FILE *in, char *__buf, size_t len) {
	size_t lost_counter = 0;
	size_t old_len      = len;

	for (size_t i = 0; i < len; i++) {
		if (!isspace(__buf[i])) {
			if (strchr(BASE64_CHAR_SET, __buf[i]) == NULL && __buf[i] != BASE64_CHAR_PADDING) {
				fprintf(stderr, "bad character encountered in base64\n");
				exit(1);
			}
			continue;
		}

		size_t local_counter = 0;
		for (; i < len && isspace(__buf[i]); i++, local_counter++, lost_counter++) {}

		i--;
		memmove(__buf + i, __buf + i + local_counter, len - i - local_counter + 1);
		len -= local_counter;
	}

	if (lost_counter == 0)
		return old_len;

	size_t sane_chars_end = old_len - lost_counter;
	size_t ret = fread(__buf + sane_chars_end, sizeof *__buf, old_len - sane_chars_end, in);
	if (ret == 0 && feof(in))
		return old_len;

	if (ferror(in)) {
		perror("error: couldn't read stream");
		exit(1);
	}

	return len;
}

/**
 * @brief Performs the actual update on the decoder buffer.
 *
 * @param __buf The buffer read from the stream and that should be decoded and kept for future read.
 *
 * @warning This function is intended for exclusive internal use.
 */
static void stream_base64_dec_update_buf(char *__buf) {
	size_t   decoded_len;
	uint8_t *decoded = base64_decode(__buf, &decoded_len);

	if (decoded_len > sizeof decoder.buf) {
		fprintf(stderr, "internal error: got bad length in decoded string\n");
		exit(1);
	}

	memset(decoder.buf, 0, sizeof decoder.buf);
	memcpy(decoder.buf, decoded, decoded_len);
	decoder.ref = decoded_len;
}

size_t stream_base64_dec(FILE *in, uint8_t *buf, size_t len) {
	memset(buf, 0, len);

	if (feof(in) && decoder.pos >= decoder.ref)
		return 0;

	size_t result;
	bool   feof_seen = false;

	for (result = 0; result < len; result++) {
		if (!decoder.buf[0] || decoder.pos >= sizeof decoder.buf) {
			decoder.pos = 0;

			char   __buf[64];
			memset(__buf, 0, sizeof __buf);
			size_t res = fread(__buf, sizeof __buf[0], sizeof __buf, in);

			if (res == sizeof __buf || (feof(in) && !feof_seen)) {
				if (feof(in))
					feof_seen = true;

				stream_sanitize_buffer(in, __buf, res);
				stream_base64_dec_update_buf(__buf);
			} else if (ferror(in)) {// error...
				perror("error: couldn't read stream");
				exit(1);
			}
		}
		buf[result] = decoder.buf[decoder.pos];
		if (feof(in) && ((!feof_seen && decoder.pos >= decoder.ref) || (feof_seen && decoder.pos + 1 >= decoder.ref)))
			return result ? result + 1 : result;
		decoder.pos++;
	}

	return result;
}

void stream_base64_seek(FILE *in, off_t off) {
	if (feof(in))
		return;

	uint8_t *buf = calloc(off, sizeof *buf);

	stream_base64_dec(in, buf, off);

	free(buf);
}

void stream_base64_reset_all() {
	memset(&decoder, 0, sizeof decoder);
	memset(&encoder, 0, sizeof encoder);
}