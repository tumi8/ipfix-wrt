#include "bzip2.h"
#include "../msg.h"

#include <bzlib.h>
#include <assert.h>

int bzip2_compression_level = 1;

void ipfix_init_compression_module(const char *params) {
	char *endptr = NULL;
	bzip2_compression_level = strtol(params, &endptr, 10);

	if (bzip2_compression_level < 1 || bzip2_compression_level > 9 ||
			endptr == params) {
		msg(MSG_ERROR, "Invalid compression level using default of 1.");
		bzip2_compression_level = 1;
	}

	DPRINTF("DEFLATE: Using compression level of %d", bzip2_compression_level);
}

int ipfix_compress(ipfix_exporter *exporter) {
	bz_stream strm;
	int ret;
	int i;

	strm.bzalloc = NULL;
	strm.bzfree = NULL;
	strm.opaque = NULL;


	// The compression level is the 100k block size - as we deal with packets
	// which can be at 65536 bytes length at most the compression level should
	// not make a difference.
	ret = BZ2_bzCompressInit(&strm, bzip2_compression_level, 0, 0);
	if (ret != BZ_OK) {
		return -1;
	}

	strm.avail_out = sizeof(exporter->compression_buffer);
	strm.next_out = (char *) exporter->compression_buffer;

	for (i = 0; i < exporter->data_sendbuffer->committed; i++) {
		if (strm.avail_out <= 0) {
			msg(MSG_ERROR, "Out of buffer space while compressing.");
			BZ2_bzCompressEnd(&strm);

			return -1;
		}

		struct iovec *vec = &exporter->data_sendbuffer->entries[i];
		strm.avail_in = vec->iov_len;
		strm.next_in = vec->iov_base;

		ret = BZ2_bzCompress(&strm, BZ_RUN);
		assert(ret == BZ_RUN_OK);
	}

	strm.avail_in = 0;
	strm.next_in = NULL;
	ret = BZ2_bzCompress(&strm, BZ_FINISH);
	assert(ret == BZ_STREAM_END);

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

	BZ2_bzCompressEnd(&strm);

	return 0;
}
