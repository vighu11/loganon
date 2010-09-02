//A lots of code stoled of netexpect, don't bother because it's just a example to use on loganon.
//We have to extract important things of this code and learn how to use edt struct to get http headers and stuff.


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#include <pcap.h>
#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/packet.h> /* Apparently only for CHAR_ASCII */
#include "cfile.h" /* Should be provided by libwireshark. Needed to avoid
		      compiler error when including epan/column.h */
#include <epan/column.h>
#include <epan/prefs.h>

#include "print.h"

#define DEF_NUM_COLS 6 /* From epan/prefs.c */
#define CHAR_ASCII 0



static int verbose;

static void read_failure_message(const char *, int);
static void failure_message(const char *, va_list);
static void open_failure_message(const char *, int, gboolean);

static nstime_t first_ts;
static nstime_t prev_cap_ts;

static int ll_type;

static column_info cinfo;

void fill_framedata(frame_data *fdata, uint64_t frame_number,
		  const struct pcap_pkthdr *h, int ll_type)
{
    fdata->next = NULL;
    fdata->prev = NULL;
    fdata->pfd = NULL;
    fdata->num = frame_number;
    fdata->pkt_len = h->len;
    fdata->cum_bytes  = 0; 
    fdata->cap_len = h->caplen;
    fdata->file_off = 0; 
    fdata->lnk_t = ll_type;
    fdata->abs_ts.secs = h->ts.tv_sec;
    fdata->abs_ts.nsecs = h->ts.tv_usec*1000;
    fdata->flags.passed_dfilter = 0;
    fdata->flags.encoding = CHAR_ASCII;
    fdata->flags.visited = 0;
    fdata->flags.marked = 0;
    fdata->flags.ref_time = 0;
    fdata->color_filter = NULL;

    /*
     * If we don't have the timestamp of the first packet in the capture, it's
     * because this is the first packet. Save the timestamp of this packet as
     * the timestamp of the first packet.
     */
    if (nstime_is_unset(&first_ts) )
	first_ts = fdata->abs_ts;

    /* Get the time elapsed between the first packet and this packet. */
    nstime_delta(&fdata->rel_ts, &fdata->abs_ts, &first_ts);

    /*
     * If we don't have the time stamp of the previous captured packet, it's
     * because this is the first packet.  Save the time stamp of this packet as
     * the time stamp of the previous captured packet.
     */
    if (nstime_is_unset(&prev_cap_ts) )
	prev_cap_ts = fdata->abs_ts;

    /*
     * Get the time elapsed between the previous captured packet and this
     * packet.
     */
    nstime_delta(&fdata->del_cap_ts, &fdata->abs_ts, &prev_cap_ts);

    /*
     * We treat delta between this packet and the previous captured packet
     * and delta between this packet and the previous displayed packet
     * as the same.
     */
    fdata->del_dis_ts = fdata->del_cap_ts;

    prev_cap_ts = fdata->abs_ts;
}

/* Free up all data attached to a "frame_data" structure. */
static void
clear_fdata(frame_data *fdata)
{
    if (fdata->pfd)
	g_slist_free(fdata->pfd);
}

/*
 * Callback function for libpcap's pcap_loop.
 */
static void
process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    (void) user; /* To eliminate compiler warning about unused variable */
    epan_dissect_t *edt;
    frame_data fdata;
    union wtap_pseudo_header pseudo_header;
    static uint32_t frame_number; /* Incremented each time libpcap gives us
				     a packet */

    memset(&pseudo_header, 0, sizeof(pseudo_header) );

    frame_number++;

    fill_framedata(&fdata, frame_number, h, ll_type);

    edt = epan_dissect_new(verbose /* create_proto_tree */,
			   verbose /* proto_tree_visible */);

#if 0
    epan_dissect_prime_dfilter(edt, cf->rfcode);
#endif

    /*
     * epan_dissect_t *edt
     * void *pseudo_header -> wtap_phdr(cf->wth)
     * const guint8 *pd -> wtap_buf_ptr(cf->wth)
     * frame_data *fd -> fill_framedata(&fdata, cf, whdr, offset);
     * column_info *cinfo
     */
    epan_dissect_run(edt, &pseudo_header, bytes, &fdata,
		     !verbose ? &cinfo : NULL);

    /*
     * Print dissected packet.
     */
    if (verbose)
	proto_tree_print(edt);
//    else {
//	epan_dissect_fill_in_columns(edt, 0, 0);
//	print_columns(&cinfo);
//    }
	/* We have to learn how use edt to print only http stuff */

    epan_dissect_free(edt);
    clear_fdata(&fdata);
}

/*
 * Initialized everything related to libwireshark use. Lots of this comes
 * from tshark.c. Not well docummented because this is standard of wireshark..
 */
static void init_libwireshark(void)
{
    int i;
    e_prefs *prefs;
    char *gpf_path, *pf_path;
    int gpf_open_errno, gpf_read_errno;
    int pf_open_errno, pf_read_errno;

    /* Needed only when using columns */
    timestamp_set_type(TS_RELATIVE);
//	printf("Error here");
//proto_register_http
//
//
    get_credential_info();
    epan_init(register_all_protocols, register_all_protocol_handoffs,
	      NULL, NULL, failure_message, open_failure_message,
	      read_failure_message, NULL);

    /*
     * Register the preferences for any non-dissector modules.
     * We must do that before we read the preferences.
     */
    prefs_register_modules();

    prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
		       &pf_open_errno, &pf_read_errno, &pf_path);
    if (gpf_path != NULL) {
	if (gpf_open_errno != 0)
	    fprintf(stderr, "Can't open global preferences file \"%s\": %s.\n",
		    pf_path, strerror(gpf_open_errno) );
	if (gpf_read_errno != 0)
	    fprintf(stderr, "I/O error reading global preferences file "
		    "\"%s\": %s.\n", pf_path, strerror(gpf_read_errno) );
    }

    if (pf_path != NULL) {
	if (pf_open_errno != 0)
	    fprintf(stderr, "Can't open your preferences file \"%s\": %s.\n",
		    pf_path, strerror(pf_open_errno));
	if (pf_read_errno != 0)
	    fprintf(stderr, "I/O error reading your preferences file "
		    "\"%s\": %s.\n", pf_path, strerror(pf_read_errno));
	g_free(pf_path);
	pf_path = NULL;
    }

/* This code should be used if you want use formatted dissector output, but It's have strange behavior. I need to read more about it */
/*    if (!verbose) {
	/* Build the column format array 
	col_setup(&cinfo, prefs->num_cols);

	for (i = 0; i < cinfo.num_cols; i++) {
	    cinfo.col_fmt[i] = get_column_format(i);
	    cinfo.col_title[i] = g_strdup(get_column_title(i));
	    cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean)
						       *NUM_COL_FMTS);
	    get_column_format_matches(cinfo.fmt_matx[i], cinfo.col_fmt[i]);
	    cinfo.col_data[i] = NULL;
	    if (cinfo.col_fmt[i] == COL_INFO)
		cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar)
						      *COL_MAX_INFO_LEN);
	    else
		cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar)
						      *COL_MAX_LEN);
	    cinfo.col_fence[i] = 0;
	    //cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar)*COL_MAX_LEN);
	    //cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar)
	//					       *COL_MAX_LEN);
	}

	for (i = 0; i < cinfo.num_cols; i++) {
	    int j;

	    for (j = 0; j < NUM_COL_FMTS; j++) {
		if (!cinfo.fmt_matx[i][j])
		    continue;

		if (cinfo.col_first[j] == -1)
		    cinfo.col_first[j] = i;

		cinfo.col_last[j] = i;
	    }
	}
    }*/

    /* Initialize all data structures used for dissection. */
    init_dissection();

    nstime_set_unset(&first_ts);
    nstime_set_unset(&prev_cap_ts);
}

int
main(int argc, char **argv)
{
    int retval, opt;
    char *iface = NULL; pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *pcap_path = NULL;
    int snaplen = 65535;
    struct bpf_program fcode;

    while ( (opt = getopt(argc, argv, "vip:s:") ) != -1) {
	switch (opt) {
	case 'v':
	    verbose = 1;
	    break;
	case 'i':
	    iface = optarg;
	    break;
	case 'p':
		pcap_path = optarg;
		break;
	case 's':
	    snaplen = atoi(optarg);
	    if (snaplen < 0 || snaplen > 65535) {
		fprintf(stderr, "invalid snaplen %s\n", optarg);
		exit(EXIT_FAILURE);
	    }

	    if (snaplen == 0)
		snaplen = 65535;
	    break;
	default:
	    fprintf(stderr, " %s [-p pcap_file] [-i iface] [-s snaplen] [PCAP filter]\n",
		    argv[0]);
	    exit(EXIT_FAILURE);
	}
    }
   verbose = 1; //Do not use with columns stuff

   if (iface == NULL && pcap_path == NULL) {
	/* User didn't specify an interface; let PCAP decide what to use */
	if ( (iface = pcap_lookupdev(errbuf) ) == NULL) {
	    fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}
       pd = pcap_open_live(iface, snaplen, 1, 1, errbuf);
    }
   else {
	if (pcap_path != NULL){
	    pd = pcap_open_offline(pcap_path, errbuf);	
	}
	else
	    pd = pcap_open_live(iface, snaplen, 1, 1, errbuf);

   }

    //iface = argv[argc-1];

    *errbuf = '\0';

    //pd = pcap_open_offline(iface, errbuf);



    if (!pd) {
	fprintf(stderr, "pcap_open_live(): %s", errbuf);
	exit(EXIT_FAILURE);
    } else if (*errbuf)
	printf("Warning: %s", errbuf);

    if (argv[optind] != NULL) {
	if (pcap_compile(pd, &fcode, argv[optind], 1, 0) < 0) {
	    fprintf(stderr, "Can't compile filter: %s", pcap_geterr(pd) );
	    pcap_close(pd);
	    exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(pd, &fcode) < 0) {
	    pcap_freecode(&fcode);
	    fprintf(stderr, "Can't set filter: %s", pcap_geterr(pd) );
	    pcap_close(pd);
	    exit(EXIT_FAILURE);
	}

	/*
	 * pcap(3) says that we can release the memory used by the BPF
	 * program after it has been made the filter program via a call to
	 * pcap_setfilter().
	 */
	pcap_freecode(&fcode);
    }

    ll_type = pcap_datalink(pd); /* Need to use
				    wtap_pcap_encap_to_wtap_encap()? */

    init_libwireshark();
	printf("Here");
    printf("libpcap version %s\n"
	   "Wireshark Packet Analizer version %s\n"
	   "Listening on interface %s\n",
	   pcap_lib_version(), epan_get_version(), iface);

    retval = pcap_loop(pd, -1, process_packet, NULL);
    if (retval == -1) {
	pcap_perror(pd, "wshark-test: ");
	pcap_close(pd);
	exit(EXIT_FAILURE);
    }

    /* Never reached */

#if 0
    cleanup_dissection()
#endif

    epan_cleanup();

    pcap_close(pd);

    return EXIT_SUCCESS;
}

static void
read_failure_message(const char *filename, int err)
{
    fprintf(stderr, "An error occurred while reading from the file \"%s\": %s.",
	    filename, strerror(err) );
}

static void
failure_message(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
    fprintf(stderr, "open error. filename = %s, err = %d, for_writing = %d\n",
	    filename, err, for_writing);
}
