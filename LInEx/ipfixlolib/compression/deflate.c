#include "deflate.h"
#include "../msg.h"

#include <zlib.h>
#include <assert.h>

int bzip2_compression_level = 9;

void ipfix_init_compression_module(const char *params) {
	char *endptr = NULL;
	bzip2_compression_level = strtol(params, &endptr, 10);

	if (bzip2_compression_level < 0 || bzip2_compression_level > 9 ||
			endptr == params) {
		msg(MSG_ERROR, "Invalid compression level using default of 9.");
		bzip2_compression_level = 9;
	}

	DPRINTF("DEFLATE: Using compression level of %d", bzip2_compression_level);
}

int ipfix_compress(ipfix_exporter *exporter) {
	z_stream strm;
	int ret;
	int i;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	ret = deflateInit(&strm, bzip2_compression_level);
	if (ret != Z_OK) {
		return -1;
	}

	strm.avail_out = sizeof(exporter->compression_buffer);
	strm.next_out = exporter->compression_buffer;

	for (i = 0; i < exporter->data_sendbuffer->committed; i++) {
		if (strm.avail_out <= 0) {
			msg(MSG_ERROR, "Out of buffer space while compressing.");
			deflateEnd(&strm);

			return -1;
		}

		struct iovec *vec = &exporter->data_sendbuffer->entries[i];
		strm.avail_in = vec->iov_len;
		strm.next_in = vec->iov_base;

		ret = deflate(&strm, Z_NO_FLUSH);
		assert(ret != Z_STREAM_ERROR);
	}

	strm.avail_in = 0;
	strm.next_in = NULL;
	ret = deflate(&strm, Z_FINISH);
	assert(ret != Z_STREAM_ERROR);

	DPRINTF("(Un-)Compressed length: %d / %d", exporter->data_sendbuffer->committed_data_length,
			sizeof(exporter->compression_buffer) - strm.avail_out);

	exporter->data_sendbuffer->entries[0].iov_base =
			exporter->compression_buffer;
	exporter->data_sendbuffer->entries[0].iov_len =
			sizeof(exporter->compression_buffer) - strm.avail_out;
	exporter->data_sendbuffer->committed = 1;
	exporter->data_sendbuffer->current = 1;
	exporter->data_sendbuffer->committed_data_length =
			exporter->data_sendbuffer->entries[0].iov_len;

	deflateEnd(&strm);

	return 0;
}
