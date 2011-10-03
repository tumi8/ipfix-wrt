#include "quicklz.h"
#include "../msg.h"
#include "ext/quicklz.h"

#include <assert.h>

// Declare compression state outside of local scope to prevent stack overflow
// See QuickLZ manual.
qlz_state_compress state_compress;

int ipfix_compress(ipfix_exporter *exporter) {
	int i;

	memset(&state_compress, 0, sizeof(qlz_state_compress));

	char *buffer = (char *) exporter->compression_buffer;
	char *const buffer_end = buffer + sizeof(exporter->compression_buffer);

	for (i = 0; i < exporter->data_sendbuffer->committed; i++) {
		struct iovec *vec = &exporter->data_sendbuffer->entries[i];

		// QuickLZ requires at least input data + 400 bytes in the output
		// buffer.
		if (buffer + (vec->iov_len + 400) > buffer_end) {
			msg(MSG_ERROR, "Out of buffer space while compressing.");

			return -1;
		}

		buffer += qlz_compress(vec->iov_base, buffer, vec->iov_len, &state_compress);
	}

	DPRINTF("(Un-)Compressed length: %d / %d", exporter->data_sendbuffer->committed_data_length,
			(buffer - (char *) exporter->compression_buffer));

	exporter->data_sendbuffer->entries[0].iov_base =
			exporter->compression_buffer;
	exporter->data_sendbuffer->entries[0].iov_len =
			buffer - (char *) exporter->compression_buffer;
	exporter->data_sendbuffer->committed = 1;
	exporter->data_sendbuffer->current = 1;
	exporter->data_sendbuffer->committed_data_length =
			exporter->data_sendbuffer->entries[0].iov_len;

	return 0;
}
