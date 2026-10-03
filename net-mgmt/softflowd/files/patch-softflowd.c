FreeBSD's bpf(4) treats a read timeout of 0 as "wait until the buffer is
full", so on a quiet interface softflowd saw no packets for a long time and
exported flows late, in large batches. Use a 1 second timeout so poll(2)
wakes up and pending packets are processed.

--- softflowd.c.orig	2026-10-03 14:06:43.489553400 +0200
+++ softflowd.c	2026-10-03 14:06:43.534914800 +0200
@@ -1575,7 +1575,7 @@
   if (dev != NULL) {
     if (!snaplen)
       snaplen = need_v6 ? LIBPCAP_SNAPLEN_V6 : LIBPCAP_SNAPLEN_V4;
-    if ((*pcap = pcap_open_live (dev, snaplen, 1, 0, ebuf)) == NULL) {
+    if ((*pcap = pcap_open_live (dev, snaplen, 1, 1000, ebuf)) == NULL) {
       fprintf (stderr, "pcap_open_live: %s\n", ebuf);
       exit (1);
     }
