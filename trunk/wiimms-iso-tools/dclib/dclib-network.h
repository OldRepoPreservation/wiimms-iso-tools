
/***************************************************************************
 *                                                                         *
 *                     _____     ____                                      *
 *                    |  __ \   / __ \   _     _ _____                     *
 *                    | |  \ \ / /  \_\ | |   | |  _  \                    *
 *                    | |   \ \| |      | |   | | |_| |                    *
 *                    | |   | || |      | |   | |  ___/                    *
 *                    | |   / /| |   __ | |   | |  _  \                    *
 *                    | |__/ / \ \__/ / | |___| | |_| |                    *
 *                    |_____/   \____/  |_____|_|_____/                    *
 *                                                                         *
 *                       Wiimms source code library                        *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *        Copyright (c) 2012-2018 by Dirk Clemens <wiimm@wiimm.de>         *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   See file gpl-2.0.txt or http://www.gnu.org/licenses/gpl-2.0.txt       *
 *                                                                         *
 ***************************************************************************/

#ifndef DCLIB_NETWORK_H
#define DCLIB_NETWORK_H 1

#include "dclib-debug.h"
#include "dclib-system.h"
#include "dclib-basics.h"
#include "dclib-file.h"

//
///////////////////////////////////////////////////////////////////////////////
///////////////			host name support		///////////////
///////////////////////////////////////////////////////////////////////////////
// [[NetworkHost_t]]

typedef struct NetworkHost_t
{
    bool	ip4_valid;	// true: 'ip4' is valid
    u32		ip4;		// ip4 or 0 if invalid
    int		port;		// port number, <0: invalid
    ccp		name;		// NULL or pointer to canonicalized name
    struct sockaddr_in sa;	// setup for AF_INET if 'ip4_valid'

    ccp		filename;	// not NULL: unix filename detected
				//	in this case: ip4_valid := FALSE
    mem_t	not_scanned;	// (0,0) or not by ResolveHost*() scanned name
}
NetworkHost_t;

//-----------------------------------------------------------------------------

static inline void InitializeHost ( NetworkHost_t *host )
	{ memset(host,0,sizeof(*host)); }

static inline void ResetHost ( NetworkHost_t *host )
	{ FREE((char*)host->name); memset(host,0,sizeof(*host)); }

static inline ccp GetHostName ( NetworkHost_t *host )
	{ return host->name ? host->name : PrintIP4(0,0,host->ip4,-1); }

//-----------------------------------------------------------------------------

bool ResolveHost
(
    // returns TRUE (=ip4_valid), if a hostname is detected
    // if result is FALSE => check host->filename

    NetworkHost_t *host,	// valid pointer to NetworkHost_t
    bool	init_host,	// true: initialize 'host'
    ccp		name,		// name to analyze
    int		default_port,	// use this as port, if no other is found
    bool	check_filename,	// true: check for unix filename
    bool	store_name	// true: setup 'host->name'
);

bool ResolveHostMem
(
    // returns TRUE (=ip4_valid), if a hostname is detected
    // if result is FALSE => check host->filename

    NetworkHost_t *host,	// valid pointer to NetworkHost_t
    bool	init_host,	// true: initialize 'host'
    mem_t	name,		// name to analyze
    int		default_port,	// use this as port, if no other is found
    bool	check_filename,	// true: check for unix filename
    bool	store_name	// true: setup 'host->name'
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			struct AllowIP4_t		///////////////
///////////////////////////////////////////////////////////////////////////////

// standard values
#define ALLOW_MODE_DENY		0	// access denied
#define ALLOW_MODE_ALLOW	1	// access allowed

// locations
#define ALLOW_MODE_EXTERN	0x001	// keyword 'EXTERN' set
#define ALLOW_MODE_LAN		0x002	// keyword 'LAN' set
#define ALLOW_MODE_LOCAL	0x004	// keyword 'LOCAL' set

// users
#define ALLOW_MODE_PUBLIC	0x010	// keyword 'PUBLIC' set
#define ALLOW_MODE_USER		0x020	// keyword 'USER' set
#define ALLOW_MODE_MOD		0x040	// keyword 'MOD' or 'MODERATOR' set
#define ALLOW_MODE_ADMIN	0x080	// keyword 'ADMIN' or 'ADMINISTRATOR' set
#define ALLOW_MODE_DEVELOP	0x100	// keyword 'DEVELOP' or 'DEVELOPER' set

// logging
#define ALLOW_MODE_LOG		0x200	// keyword 'LOG' set
#define ALLOW_MODE_VERBOSE	0x400	// keyword 'VERBOSE' set

// special processing values
#define ALLOW_MODE_NOT		0x1000000000000000ull	// negate bits
#define ALLOW_MODE_SET		0x2000000000000000ull	// set bits, ignore AND
#define ALLOW_MODE_AND		0x4000000000000000ull	// use AND operation (otherwise OR)
#define ALLOW_MODE_CONTINUE	0x8000000000000000ull	// continue search (otherwise break)

#define ALLOW_MODE__OP		0x6000000000000000ull	// mask for operation
#define ALLOW_MODE__MASK	0x0fffffffffffffffull	// mask out control bits

//-----------------------------------------------------------------------------
// [[AllowIP4Item_t]]

typedef struct AllowIP4Item_t
{
    u32		addr;		// IP address
    u32		mask;		// netmask
    u64		mode;		// new mode, see ALLOW_MODE_*
    u64		count;		// incremented on IP match
}
AllowIP4Item_t;

//-----------------------------------------------------------------------------
// [[AllowIP4_t]]

typedef struct AllowIP4_t
{
    AllowIP4Item_t	*list;		// list of addresses, alloced
    uint		used;		// number of used elements
    uint		size;		// number of alloced elements

    int			ref_counter;	// reference counter

    // for automatic usage
    u64			fallback_mode;	// mode if IP not found
    u64			allow_mode;	// allow, if any of these bits is set
}
AllowIP4_t;

///////////////////////////////////////////////////////////////////////////////

void InitializeAllowIP4 ( AllowIP4_t *ai );
void ResetAllowIP4 ( AllowIP4_t *ai );
void ClearAllowIP4 ( AllowIP4_t *ai );

// if ai==NULL: create a new ai
AllowIP4_t * NewReferenceAllowIP4 ( AllowIP4_t *ai );

//returns always NULL
AllowIP4_t * DeleteReferenceAllowIP4 ( AllowIP4_t *ai );

void DumpAllowIP4
(
    FILE		*f,		// NULL or output file
    int			indent,		// indention
    const AllowIP4_t	*ai,		// NULL or source
    ccp			title,		// not NULL: Add title
    bool		print_tab_head	// true: add table headings and separators
);

//-----------------------------------------------------------------------------

enumError ScanLineAllowIP4
(
    AllowIP4_t		*ai,	// valid structure; new elements are appended
    mem_t		line,	// single line to analyse
    const KeywordTab_t	*tab	// NULL or keyword table.
				// If NULL, a local table with keywords 0 DENY
				// ALLOW SET REMOVE AND OR and CONTINUE is used.
);

enumError ScanFileAllowIP4
(
    AllowIP4_t		*ai,	// valid structure; new elements are appended
    ccp			fname,	// ffilename of the source
    FileMode_t		fmode,	// flags for OpenFile()
    const KeywordTab_t	*tab	// NULL or keyword table -> see ScanLineAllowIP4()
);

//-----------------------------------------------------------------------------

void ResetCountersAllowIP4
(
    AllowIP4_t		*ai		// NULL or dest for addition
);

void AddCountersAllowIP4
(
    AllowIP4_t		*dest,		// NULL or dest for addition
    const AllowIP4_t	*src		// NULL or source for addition
);

//-----------------------------------------------------------------------------

// if found, result is masked by ALLOWIP4_MODE__MASK
u64 GetAllowIP4ByAddr ( const AllowIP4_t *ai, u32   addr, u64 if_not_found );
u64 GetAllowIP4ByName ( const AllowIP4_t *ai, mem_t name, u64 if_not_found );

// if ai==NULL => return ALLOW_MODE_ALLOW
// if found, result is masked by ALLOWIP4_MODE__MASK and by 'ai->allow_mode'
// if not found, 'ai->fallback_mode' is returned.
u64 GetAutoAllowIP4ByAddr ( const AllowIP4_t *ai, u32   addr );
u64 GetAutoAllowIP4ByName ( const AllowIP4_t *ai, mem_t name );
u64 GetAutoAllowIP4BySock ( const AllowIP4_t *ai, int   sock );

//-----------------------------------------------------------------------------

void SaveCurrentStateAllowIP4
(
    FILE		*f,		// output file
    ccp			section,	// not NULL: create own section
    ccp			name_prefix,	// NULL or prefix of name
    uint		tab_pos,	// tab pos of '='
    const AllowIP4_t	*ai		// valid struct
);

//-----------------------------------------------------------------------------

bool ScanAllowIP4Item
(
    // return true on success; counter is optional

    AllowIP4Item_t	*it,	// store data here, cleared first
    ccp			line	// NULL or line to scan
);

void RestoreStateAllowIP4
(
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    cvp			user_table	// pointer provided by RestoreStateTab_t[]
);

void RestoreStateAllowIP4Ex
(
    RestoreState_t	*rs,		// info data, modified
    AllowIP4_t		*ai,		// valid struct
    ccp			name_prefix	// NULL or prefix of name
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			TCP + UDP connections		///////////////
///////////////////////////////////////////////////////////////////////////////

int ConnectByHost
(
    NetworkHost_t *host,	// valid pointer to NetworkHost_t
    int		type,		// AF_INET type, e.g. SOCK_STREAM, SOCK_DGRAM
    int		protocol,	// AF_INET protocol, e.g. IPPROTO_TCP, IPPROTO_UDP
    bool	silent		// true: suppress error messages
);

///////////////////////////////////////////////////////////////////////////////

int ConnectByHostTCP
(
    NetworkHost_t *host,	// valid pointer to NetworkHost_t
    bool	silent		// true: suppress error messages
);

int ConnectTCP
(
    ccp		name,		// optional service + server + optional host
				//   e.g.: "service://host:port/....."
    int		default_host,	// default host
    bool	silent		// true: suppress error messages
);

int ConnectNumericTCP
(
    // like ConnectTCP(), but without name resolution (only numeric ip+port)

    ccp		addr,		// TCP address: ['tcp':] IPv4 [:PORT]
    int		default_port,	// NULL or default port, if not found in 'addr'
    bool	silent		// true: suppress error messages
);

extern int (*ConnectTCP_Hook)
(
    // if set: ConnectNumericTCP() uses ConnectTCP()

    ccp		addr,		// TCP address: ['tcp':] IPv4 [:PORT]
    int		default_port,	// NULL or default port, if not found in 'addr'
    bool	silent		// true: suppress error messages
);

void Setup_ConnectTCP_Hook ( bool force );

int ConnectUnixTCP
(
    ccp		fname,		// unix socket filename
    bool	silent		// true: suppress error messages
);

///////////////////////////////////////////////////////////////////////////////

int ConnectByHostUDP
(
    NetworkHost_t *host,	// valid pointer to NetworkHost_t
    bool	silent		// true: suppress error messages
);

int ConnectUDP
(
    ccp		name,		// optional service + server + optional host
				//   e.g.: "service://host:port/....."
    int		default_host,	// default host
    bool	silent		// true: suppress error messages
);

///////////////////////////////////////////////////////////////////////////////

int WillReceiveNotBlock
(
    // returns: -1:error, 0:may block, 1:will not block

    int		fd,		// file handle of source
    uint	msec		// timeout: 0:no timeout, >0: milliseconds
);

int WillSendNotBlock
(
    // returns: -1:error, 0:may block, 1:will not block

    int		fd,		// file handle of source
    uint	msec		// timeout: 0:no timeout, >0: milliseconds
);

///////////////////////////////////////////////////////////////////////////////

ssize_t ReceiveTimeout
(
    // returns: <0: on error, 0:timeout, >0: bytes read

    int		fd,		// file handle of source
    void	*buf,		// valid pointer to buffer
    uint	size,		// size to receive
    int		flags,		// flags for recv()
    int		msec		// timeout: -1:unlimited, 0:no timeout, >0: milliseconds
);

ssize_t SendTimeout
(
    // returns: <0: on error, 0:timeout, >0: bytes written

    int		fd,		// file hande of destination
    const void	*data,		// valid pointer to data
    uint	size,		// size to receive
    int		flags,		// flags for send()
    int		msec,		// total timeout: -1:unlimited, 0:no timeout, >0: milliseconds
    bool	all		// true: send all data until done, total timeout or error
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			IP data structures		///////////////
///////////////////////////////////////////////////////////////////////////////
// [[ether_head_t]]

typedef struct ether_head_t
{
    // http://en.wikipedia.org/wiki/Ethertype

    u8		mac_dest[6];
    u8		mac_src[6];
    u16		ether_type;
}
__attribute__ ((packed)) ether_head_t;

//-----------------------------------------------------------------------------
// [[ip4_head_t]]

typedef struct ip4_head_t
{
    // http://de.wikipedia.org/wiki/IP-Paket

    u8		vers_ihl;	// high nibble: version, low nibble: IHL (Ip Header Len)
    u8		tos;
    u16		total_len;
    u16		id;
    u16		frag_off;	// low 12 bits: fragment offset, high 4 bits: flags
    u8		ttl;
    u8		protocol;
    u16		checksum;
    u32		ip_src;
    u32		ip_dest;
    // optional: options + padding
}
__attribute__ ((packed)) ip4_head_t;

//-----------------------------------------------------------------------------
// [[udp_head_t]]

typedef struct udp_head_t
{
    // http://de.wikipedia.org/wiki/User_Datagram_Protocol#UDP-Datagramm

    u16		port_src;
    u16		port_dest;
    u16		data_len;
    u16		checksum;
}
__attribute__ ((packed)) udp_head_t;

//-----------------------------------------------------------------------------
// [[udp_packet_t]]

// ethernet packet limit is 1500
#define MAX_UDP_PACKET_DATA ( 1500 - sizeof(ip4_head_t) - sizeof(udp_head_t) )

typedef struct udp_packet_t
{
    ip4_head_t	ip4;
    udp_head_t	udp;
    u8		data[MAX_UDP_PACKET_DATA];
}
__attribute__ ((packed)) udp_packet_t;


//
///////////////////////////////////////////////////////////////////////////////
///////////////			IP interface			///////////////
///////////////////////////////////////////////////////////////////////////////

char * ScanNumericIP4
(
    // returns next unread character or NULL on error

    ccp		addr,		// address to scan
    u32		*r_ipv4,	// not NULL: store result here (local endian)
    u32		*r_port,	// not NULL: scan port too (local endian)
    uint	default_port	// return this if no port found
);

//-----------------------------------------------------------------------------

mem_t ScanNumericIP4Mem
(
    // returns unread character or NullMem on error

    mem_t	addr,		// address to scan
    u32		*r_ipv4,	// not NULL: store result here (local endian)
    u32		*r_port,	// not NULL: scan port too (local endian)
    uint	default_port	// return this if no port found
);

//-----------------------------------------------------------------------------

// Returns a NETWORK MASK "/a.b.c.d" or as CIDR number "/num" between 0 and 32.
// An optional slash '/' at the beginning is skipped.
// Returns modified 'source' if a MASK or CDIR is detected.
// If no one is detected, source is unmodified and returned mask = ~0.

mem_t ScanNetworkMaskMem ( u32 *mask, mem_t source );

//-----------------------------------------------------------------------------

u16 CalcChecksumIP4
(
    const void		*data,	// ip4 header
				// make sure, that the checksum member is NULL
    uint		size	// size of ip4 header
);

//-----------------------------------------------------------------------------

u16 CalcChecksumUDP
(
    const ip4_head_t	*ip4,	// IP4 header
    const udp_head_t	*udp,	// UDP header
    const void		*data	// UDP data, size is 'udp->data_len'
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			UNIX sockets			///////////////
///////////////////////////////////////////////////////////////////////////////

enumError SendUnixUDP
(
    ccp		path1,		// NULL or part #1 of path
    ccp		path2,		// NULL or part #2 of path
    bool	silent,		// suppress all error messages
    cvp		data,		// data to send
    uint	size		// size of 'data'
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			Transfer Statistics		///////////////
///////////////////////////////////////////////////////////////////////////////
// [[TransferStats_t]]

typedef struct TransferStats_t
{
    u32 conn_count;	// number of connections
    u32 recv_count;	// number of received packets
    u64 recv_size;	// total size of received packets
    u32 send_count;	// number of send packets
    u64 send_size;	// total size of send packets
}
TransferStats_t;

//-----------------------------------------------------------------------------

static inline void InitializeTransferStats ( TransferStats_t *ts )
	{ DASSERT(ts); memset(ts,0,sizeof(*ts)); }

//-----------------------------------------------------------------------------

TransferStats_t * Add2TransferStats
(
    // return dest
    // calculate: dest += src

    TransferStats_t		*dest,	// NULL or destination and first source
    const TransferStats_t	*src	// NULL or second source
);

TransferStats_t * Sub2TransferStats
(
    // return dest
    // calculate: dest -= src

    TransferStats_t		*dest,	// NULL or destination and first source
    const TransferStats_t	*src	// NULL or second source
);

TransferStats_t * Add3TransferStats
(
    // return dest
    // calculate: dest = src1 + src2

    TransferStats_t		*dest,	// NULL or destination (maybe same as source)
    const TransferStats_t	*src1,	// NULL or first source
    const TransferStats_t	*src2	// NULL or second source
);

TransferStats_t * Sub3TransferStats
(
    // return dest
    // calculate: dest = src1 - src2

    TransferStats_t		*dest,	// NULL or destination (maybe same as source)
    const TransferStats_t	*src1,	// NULL or first source
    const TransferStats_t	*src2	// NULL or second source
);

TransferStats_t * SumTransferStats
(
    // return dest
    // calculate: dest = sum(all_sources)

    TransferStats_t		*dest,	// NULL or destination (maybe same as source)
    const TransferStats_t * const *src,	// NULL or source list, elements may be NULL
    int				n_src	// number of element; if -1: term at first NULL
);

ccp PrintTransferStatsSQL
(
    // print statistic as SQL assigning list.
    // arguments are speparated by a comma.

    char			*buf,		// result buffer
						// NULL: use a local circulary static buffer
    size_t			buf_size,	// size of 'buf', ignored if buf==NULL
    const TransferStats_t	*ts,		// valid source
    ccp				prefix		// not NULL: prefix memebr names
);

//-----------------------------------------------------------------------------

void PrintTranferStatistics
(
    FILE	*f,		// output file, never NULL
    ccp		prefix,		// NULL or prefix for each line
    ccp		name,		// statistics name, up to 5 chars including colon
    const TransferStats_t *stat,// statistics record

    TransferStats_t *prev,	// NULL statistics record with previous data
    u64		duration,	// delta duration in usec
    ccp		duration_info,	// text representation of 'duration'

    const ColorSet_t *colset	// NULL (no colors) or color set to use
);

//-----------------------------------------------------------------------------

void SaveCurrentStateTransferStats
(
    FILE		*f,		// output file
    const TransferStats_t *stat		// valid stat object
);

void SaveCurrentStateTransferStats1
(
    // print as single line
    FILE		*f,		// output file
    ccp			name,		// var name; use "tfer-stat" if NULL or EMPTY
    const TransferStats_t *stat		// valid stat object
);

void SaveCurrentStateTransferStatsN
(
    // print multiple stats each as single line
    FILE		*f,		// output file
    ccp			name,		// var name; use "tfer-stat-" if NULL or EMPTY
    const TransferStats_t *stat,	// list of valid stat objects
    uint		n_stat		// number of elements in 'stat'
);

//-----------------------------------------------------------------------------

void RestoreStateTransferStats
(
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    cvp			user_table	// pointer provided by RestoreStateTab_t[]
);

void RestoreStateTransferStats1
(
    // scan single line
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    ccp			name,		// var name; use "tfer-stat" if NULL or EMPTY
    TransferStats_t	*stat,		// valid stat object
    bool		fall_back	// true: fall back to RestoreStateTransferStats()
);

uint RestoreStateTransferStatsN
(
    // print multiple stats each as single line
    // returns the number of read elements; all others are set to NULL
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    ccp			name,		// var name; use "tfer-stat-" if NULL or EMPTY
    TransferStats_t	*stat,		// list of valid stat objects
    uint		n_stat		// number of elements in 'stat'
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    Socket_t			///////////////
///////////////////////////////////////////////////////////////////////////////
// define some TCP call back function types

struct TCPStream_t;
typedef int (*TCPStreamFunc) ( struct TCPStream_t * ts );
typedef int (*TCPIOFunc)     ( struct TCPStream_t * ts, u8 *buf, uint size );
typedef int (*TCPTimeFunc)   ( struct TCPStream_t * ts, u64 now_usec );

typedef enum TCPFDList_t
{
    TCP_FM_ADD_SOCK,	// add sockets to 'fdl'
    TCP_FM_CHECK_SOCK,	// check sockts of 'fdl'
    TCP_FM_TIMEOUT,	// on timeout (fdl is NULL)
}
TCPFDList_t;

typedef int (*TCPFDListFunc)
(
    // if return <0, then don't do standard action with the stream
    struct TCPStream_t	*ts,		// valid TCP stream
    FDList_t		*fdl,		// valid socket list
    TCPFDList_t		mode,		// execution mode
    bool		check_timeout	// true: enable timeout checks
);

struct TCPHandler_t;
typedef struct TCPStream_t * (*TCPCreateFunc) ( struct TCPHandler_t * th );

///////////////////////////////////////////////////////////////////////////////
// [[Socket_t]]

typedef struct Socket_t
{
    int		sock;			// tcp socket
    uint	poll_index;		// if poll() is used: index of 'poll_list'
    bool	is_unix;		// true: Is a unix file socket
    char	info[23];		// info about this socket, for debugging

    // if defined, these function replace the TCPHandler_t functions.

    TCPCreateFunc OnCreateStream;	// not NULL: called to create
					// an initialized stream object

    TCPStreamFunc OnAddedStream;	// not NULL: called after the stream
					// is created and added
}
Socket_t;

uint GetSocketNameBySA
	( char *buf, uint bufsize, const struct sockaddr *sa, socklen_t sa_len );
uint GetSocketName ( char *buf, uint bufsize, int sock );
uint GetPeerName ( char *buf, uint bufsize, int sock );
bool DeleteSocketFile ( int sock );

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    TCPStream_t			///////////////
///////////////////////////////////////////////////////////////////////////////
// [[TCPStream_t]]

typedef struct TCPStream_t
{
    //--- double linked list

    struct TCPStream_t *prev;	// link to previous stream, unused for the pool
    struct TCPStream_t *next;	// link to next stream
    struct TCPHandler_t *handler; // related TCP handler


    //--- base data

    uint	unique_id;	// unique id, created by CreateUniqueId()
    int		sock;		// tcp socket
    uchar	protect;	// >0: protect member, don't destroy it
    uchar	auto_close;	// >0: close stream after last byte sent
    uchar	rescan;		// rescan input buffer also without new data
    uchar	eof;		// >0: end of file, bit-0 is set by framework
    uchar	error;		// >0: connection error, bit-0 is set by framework
    uchar	not_socket;	// >0: fd is not a socket! // =0: unknown
    GrowBuffer_t ibuf;		// input buffer
    GrowBuffer_t obuf;		// output buffer
    u64		accept_usec;	// >0: next trigger, not used for timeout
    u64		trigger_usec;	// >0: next timeout and trigger time
    u64		delay_usec;	// >0: delay of trigger after accept_usec
    u64		timeout_usec;	// >0: auto disconnect after inactivity
    u64		allow_mode;	// >0: access allowed with this code
    uint	poll_index;	// if 'use_poll': index of 'poll_list'


    //--- call back functions

    TCPTimeFunc OnMaintenance;	// not NULL: called on maintenance
    TCPTimeFunc OnTimeout;	// not NULL: called on timeout
    TCPIOFunc	OnReceived;	// not NULL: called after read, but before buffer insert
    TCPIOFunc	OnSend;		// not NULL: called after write, but before buffer drop
    TCPTimeFunc	OnClose;	// not NULL: called when the stream is closed
    TCPFDListFunc OnFDList;	// not NULL: Call this for FDList actions

    //--- statistics

    char	info[32];	// info about this stream, for debugging
    u64		connect_usec;	// time of connection, GetTimeUSec(false)
    u64		receive_usec;	// time of last receive, GetTimeUSec(false)
    u64		send_usec;	// time of last send, GetTimeUSec(false)

    TransferStats_t stat;	// transfer statistics
    TransferStats_t *xstat;	// NULL or pointer to summary statistics


    //--- data extension

    u8		data[0];	// user specific data
}
TCPStream_t;

///////////////////////////////////////////////////////////////////////////////

void LogTCPStream
(
    FILE		*f,		// output file
    int			indent,		// indention
    const TCPStream_t	*ts,		// valid TCP handler
    int			recurse,	// >0: print stream list, >1: print buffer status
    ccp			format,		// format string for vfprintf()
    ...					// arguments for 'vfprintf(format,...)'
)
__attribute__ ((__format__(__printf__,5,6)));

//-----------------------------------------------------------------------------

char * BufInfoHeadTCPStream
(
    // returns a pointer to the head line

    uint		line		// 0|1
);

#define BUF_INFO_TCP_STREAM_SIZE 120

char * BufInfoTCPStream
(
    // returns a pointer to the buffer

    char		* buf,		// result (BUF_INFO_TCP_STREAM_SIZE bytes are good)
					// If NULL, a local circulary static buffer is used
    size_t		buf_size,	// size of 'buf', ignored if buf==NULL
    const TCPStream_t	*ts,		// valid TCP handler
    u64			now_usec	// NULL or current time, GetTimeUSec(false)
);

//-----------------------------------------------------------------------------

void InitializeTCPStream ( TCPStream_t *ts, int sock );
void ResetTCPStream ( TCPStream_t *ts );
void DestroyTCPStream ( TCPStream_t *ts );

int SendDirectTCPStream
(
    // Send data direct without blocking and without calling any notifier.
    // If output buf is not empty or send failed, append the data to output buf.
    // Returns the number of bytes added to the output buffer or -1 on error.
    // The data is send+stored completely (returns 'size') or not at all
    // (returns '0'). -1 is returned if the socket is invalid.

    TCPStream_t		*ts,		// valid TCP handler
    bool		flush_output,	// true: try to flush out-buf before
    cvp			data,		// data to send
    uint		size		// size of 'data', If NULL && flush: flush only
);

int PrintArgDirectTCPStream
(
    // Printing interface for SendDirectTCPStream()

    TCPStream_t		*ts,		// valid TCP handler
    bool		flush_output,	// true: try to flush out-buf before
    ccp			format,		// format string for vsnprintf()
    va_list		arg		// parameters for 'vfprintf(...,format,...)'
);

int PrintDirectTCPStream
(
    // Printing interface for SendDirectTCPStream()

    TCPStream_t		*ts,		// valid TCP handler
    bool		flush_output,	// true: try to flush out-buf before
    ccp			format,		// format string for vfprintf()
    ...					// arguments for 'vfprintf(...,format,...)'
)
__attribute__ ((__format__(__printf__,3,4)));

//-----------------------------------------------------------------------------

int PrintBinary1TCPStream
(
    TCPStream_t	*ts,		// NULL or destination
    ccp		cmd,		// command name
    cvp		bin_data,	// pointer to binary data
    uint	bin_size,	// size of binary data
    ccp		format,		// NULL or format string with final ';'
    ...				// parameters for 'format'
)
__attribute__ ((__format__(__printf__,5,6)));

int PrintBinary2TCPStream
(
    TCPStream_t	*ts,		// NULL or destination
    ccp		cmd,		// command name
    cvp		bin1_data,	// pointer to binary data
    uint	bin1_size,	// size of binary data
    cvp		bin2_data,	// pointer to binary data
    uint	bin2_size,	// size of binary data
    ccp		format,		// NULL or format string with final ';'
    ...				// parameters for 'format'
)
__attribute__ ((__format__(__printf__,7,8)));

//-----------------------------------------------------------------------------

static inline int FlushTCPStream
(
    // Flush the output buffer using SendDirectTCPStream() without data

    TCPStream_t		*ts		// valid TCP handler
)
{
    return SendDirectTCPStream(ts,true,0,0);
}

//-----------------------------------------------------------------------------

ssize_t UpdateRecvStatTCPStream
(
    // returns 'send_stat'

    TCPStream_t		*ts,		// valid TCP handler
    ssize_t		recv_stat,	// result of recv(), update stats on >0
    u64			now_usec	// NULL or current time
);

ssize_t UpdateSendStatTCPStream
(
    // returns 'send_stat'

    TCPStream_t		*ts,		// valid TCP handler
    ssize_t		send_stat,	// result of send(), update stats on >0
    u64			now_usec	// NULL or current time
);

//-----------------------------------------------------------------------------

void AddSocketTCPStream
(
    TCPStream_t		*ts,		// valid TCP handler
    FDList_t		*fdl		// valid file descriptor list
);

void CheckSocketTCPStream
(
    TCPStream_t		*ts,		// valid TCP handler
    FDList_t		*fdl,		// valid socket list
    bool		check_timeout	// true: enable timeout checks
);

//-----------------------------------------------------------------------------

void CheckTimeoutTCPStream ( TCPStream_t *ts );
u64  GetLastActivityTCPStream ( TCPStream_t *ts );
u64  GetTimeoutTCPStream ( TCPStream_t *ts );
int  OnTimeoutTCPStream ( TCPStream_t *ts, u64 now_usec );
void SetupTriggerTCPStream ( TCPStream_t *ts, u64 now_usec );

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    TCPHandler_t		///////////////
///////////////////////////////////////////////////////////////////////////////

typedef int (*TCPHandlerFunc)
(
    // returns 0 on success, !=0 otherwise

    struct TCPHandler_t	*th,		// valid TCP handler
    const Socket_t	*lsock,		// valid listen-socket
    int			sock		// valid socket to verify
);

typedef bool (*TCPAllowFunc)
(
    // returns true if access is allowed

    struct TCPHandler_t	*th,		// valid TCP handler
    const Socket_t	*lsock,		// valid listen-socket
    int			sock,		// valid socket to verify
    u64			*allow		// not NULL: store allow code here
);

///////////////////////////////////////////////////////////////////////////////
// [[TCPHandler_t]]

#define TCP_HANDLER_MAX_LISTEN 3

typedef struct TCPHandler_t
{
    uint	unique_id;		// unique id, created by CreateUniqueId()
    uint	data_size;		// size of TCPStream_t::data
    uint	max_conn;		// max allowed connections

    TCPStream_t	*first;			// pointer to first active stream
    uint	need_maintenance;	// >0: a stream is ready for maintenance

    TCPAllowFunc   OnAllowStream;	// not NULL: called before allowing a connection
					// initialized with IsStreamAllowed()
    TCPHandlerFunc OnAcceptStream;	// not NULL: called before accpeting a connection
    TCPCreateFunc  OnCreateStream;	// not NULL: called to create an initialized stream object
    TCPStreamFunc  OnAddedStream;	// not NULL: called after the stream is created and added
    TCPStreamFunc  OnDestroyStream;	// not NULL: called before destroying a stream

    Socket_t listen[TCP_HANDLER_MAX_LISTEN];
					// sockets to listen

    AllowIP4_t	*allow_ip4;		// NULL or filter for accept (not for unix files).
					// Analysis is done by OnAllowStream()
					// before calling OnAcceptStream().

    //--- statistics

    uint	used_streams;		// number of currently used streams
    uint	max_used_streams;	// number of max used streams
    uint	total_streams;		// total number of used streams

    TransferStats_t stat;		// transfer statistics
}
TCPHandler_t;

///////////////////////////////////////////////////////////////////////////////

void LogTCPHandler
(
    FILE		*f,		// output file
    int			indent,		// indention
    const TCPHandler_t	*th,		// valid TCP handler
    int			recurse,	// >0: print stream list, >1: print buffer status
    ccp			format,		// format string for vfprintf()
    ...					// arguments for 'vfprintf(format,...)'
)
__attribute__ ((__format__(__printf__,5,6)));

//-----------------------------------------------------------------------------

void PrintStreamTableTCPHandler
(
    FILE		*f,		// output file
    const ColorSet_t	*colset,	// NULL (no colors) or valid color set
    int			indent,		// indention
    const TCPHandler_t	*th		// valid TCP handler
);

//-----------------------------------------------------------------------------

void InitializeTCPHandler
(
    TCPHandler_t *th,		// not NULL
    uint	data_size	// size of 'TCPStream_t::data'
);

void ResetTCPHandler
(
    TCPHandler_t *th		// valid TCP handler
);

uint CloseTCPHandler
(
    // returns the number of waiting clients (obuf not empty and !disabled)
    TCPHandler_t *th		// valid TCP handler
);

TCPStream_t * AddTCPStream
(
    TCPHandler_t *th,		// valid TCP handler
    TCPStream_t	 *ts		// the new stream
);

TCPStream_t * CreateTCPStream
(
    TCPHandler_t	*th,		// valid TCP handler
    int			sock,		// related socket
    u64			allow_mode,	// stored in 'allow_mode'
    const Socket_t	*listen		// NULL or related listen object
);

TCPStream_t * ConnectUnixTCPStream
(
    TCPHandler_t	*th,		// valid TCP handler
    ccp			path,		// NULL or path part 1 to socket file
    bool		silent		// suppress error messages
);

TCPStream_t * ConnectTCPStream
(
    TCPHandler_t	*th,		// valid TCP handler
    ccp			addr,		// address -> NetworkHost_t
    u16			default_port,	// default port
    bool		silent		// suppress error messages
);

TCPStream_t * FindTCPStreamByUniqueID
(
    TCPHandler_t	*th,		// valid TCP handler
    uint		unique_id	// id to search
);

//-----------------------------------------------------------------------------

uint NumOfSocketsTCP ( const TCPHandler_t *th );
Socket_t * GetUnusedListenSocketTCP ( TCPHandler_t *th, bool silent );

//-----------------------------------------------------------------------------

enumError ListenUnixTCP
(
    TCPHandler_t	*th,		// valid TCP handler
    ccp			path		// path to unix file
);

enumError ListenTCP
(
    TCPHandler_t	*th,		// valid TCP handler
    ccp			addr,		// IPv4 address with optional port -> NetworkHost_t
					// fall back to ListenUnixTCP() if addr begins with
					// 'unix:' or '/' or './ or '../'
    u16			default_port	// default port
);

int UnlistenTCP
(
    // returns the index of the closed socket, or if not found

    TCPHandler_t	*th,		// valid TCP handler
    int			sock		// socket to close
);

uint UnlistenAllTCP
(
    // returns the number of closed sockets

    TCPHandler_t	*th		// valid TCP handler
);

//-----------------------------------------------------------------------------

void AddSocketsTCP
(
    TCPHandler_t	*th,		// valid TCP handler
    FDList_t		*fdl		// valid file descriptor list
);

//-----------------------------------------------------------------------------

bool IsStreamAllowed
(
    // returns true if access is allowed

    struct TCPHandler_t	*th,		// valid TCP handler
    const Socket_t	*lsock,		// valid listen-socket
    int			sock,		// valid socket to verify
    u64			*allow		// not NULL: store allow code here
);

TCPStream_t * OnAcceptStream
(
    TCPHandler_t	*th,		// valid TCP handler
    const Socket_t	*lsock,		// listen-socket
    u64			now_usec	// time for timestamps, GetTimeUSec(false)
);

void OnCloseStream
(
    TCPStream_t		*ts,		// valid TCP stream
    u64			now_usec	// time for timestamps, GetTimeUSec(false)
);

void SetNotSocketStream
(
    TCPStream_t		*ts		// valid TCP stream
);

void OnReceivedStream
(
    TCPStream_t		*ts,		// valid TCP stream
    u64			now_usec	// time for timestamps, GetTimeUSec(false)
);

void OnWriteStream
(
    TCPStream_t		*ts,		// valid TCP stream
    u64			now_usec	// time for timestamps, GetTimeUSec(false)
);

void CheckSocketsTCP
(
    TCPHandler_t	*th,		// valid TCP handler
    FDList_t		*fdl,		// valid socket list
    bool		check_timeout	// true: enable timeout checks
);

void CheckTimeoutTCP ( TCPHandler_t *th );
bool MaintenanceTCP ( TCPHandler_t *th );

void ManageSocketsTCP
(
    // call  CheckSocketsTCP(), CheckTimeoutTCP(), MaintenanceTCP()

    TCPHandler_t	*th,		// valid TCP handler
    FDList_t		*fdl,		// valid socket list
    int			stat		// result of a WAIT function
);

///////////////////////////////////////////////////////////////////////////////
// special case: send single data packtes

TCPStream_t * SendSingleUnixTCP
(
    TCPHandler_t	*th,		// valid handle
    ccp			path,		// path to socket file

    const void		*data,		// data to send
    uint		size,		// size of 'data'
    u64			timeout_usec,	// timeout before closing the connection
    TransferStats_t	*xstat,		// NULL or pointer to summary statistics

    bool		silent		// suppress error messages
);

TCPStream_t * SendSingleTCP
(
    TCPHandler_t	*th,		// valid handle
    ccp			addr,		// address -> NetworkHost_t
    u16			default_port,	// default port

    const void		*data,		// data to send
    uint		size,		// size of 'data'
    u64			timeout_usec,	// timeout before closing the connection
    TransferStats_t	*xstat,		// NULL or pointer to summary statistics

    bool		silent		// suppress error messages
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			TCP: CommandTCP			///////////////
///////////////////////////////////////////////////////////////////////////////

typedef char * (*CommandTCPLineFunc)
(
    // return first non scanned character, or NULL on error

    TCPStream_t	*ts,		// valid stream data
    char	*line,		// begin of line
    char	*line_end,	// end of line
    u64		now_usec	// NULL or current time
);

///////////////////////////////////////////////////////////////////////////////

typedef enumError (*CommandTCPArgFunc)
(
    TCPStream_t	*ts,		// valid stream data
    int		argc,		// number of arguments in 'argv'
    char	**argv,		// array with 'argc' arguments + a NULL term
    u64		now_usec	// NULL or current time in usec
);

///////////////////////////////////////////////////////////////////////////////

typedef struct CommandTCPInfo_t
{
    //--- base parameters

    bool	comma_is_eol;		// true: comma is 'end of command line'
    u64		timeout_usec;		// wanted timeout, default 10s

    //--- scanning functions, high priority first

    CommandTCPArgFunc	OnScanArg;	// function to scan arguments
    CommandTCPLineFunc	OnScanLine;	// function to scan line

    //--- user specific data extension

    u8		data[0];
}
CommandTCPInfo_t;

///////////////////////////////////////////////////////////////////////////////

int OnCreateCommandTCP ( TCPStream_t *ts );

void SetTimeoutCommandTCP
(
    TCPStream_t	*ts,		// valid stream
    u64		now_usec	// NULL or current time in usec
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			SaveCurrentState*()		///////////////
///////////////////////////////////////////////////////////////////////////////

void SaveCurrentStateSocket
(
    FILE		*f,		// output file
    const Socket_t	*sock		// valid socket object
);

///////////////////////////////////////////////////////////////////////////////

typedef void (*TCPStreamSaveFunc)
(
    FILE		*f,		// output file
    const TCPStream_t	*ts		// valid TCP stream
);

//-----------------------------------------------------------------------------

void SaveCurrentStateTCPStream
(
    FILE		*f,		// output file
    const TCPStream_t	*ts,		// valid TCP stream
    TCPStreamSaveFunc	func		// NULL or function for 'TCPStream_t.data' extend
);

void SaveCurrentStateTCPHandler
(
    FILE		*f,		// output file
    ccp			sect_name,	// section base name
    const TCPHandler_t	*th,		// valid TCP handler
    TCPStreamSaveFunc	func		// NULL or function for 'TCPStream_t.data' extend
);

void SaveCurrentStateCommandTCP
(
    FILE		*f,		// output file
    const TCPStream_t	*ts		// valid TCP stream
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			RestoreState*()			///////////////
///////////////////////////////////////////////////////////////////////////////

void RestoreStateSocket
(
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    cvp			user_table	// pointer provided by RestoreStateTab_t[]
);

///////////////////////////////////////////////////////////////////////////////

TCPStream_t * RestoreStateTCPStream
(
    // return 'ts' or the new TCPStream_t
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    TCPStream_t		*ts,		// if NULL: create it
    uint		extra_size	// if 'ts' alloced: alloc some byte more
);

///////////////////////////////////////////////////////////////////////////////

void RestoreStateTCPHandler_base
(
    TCPHandler_t *th,			// valid TCPHandler_t
    RestoreState_t	*rs		// info data, can be modified (cleaned after call)
);

Socket_t * RestoreStateTCPHandler_socket
(
    TCPHandler_t *th,			// valid TCPHandler_t
    RestoreState_t	*rs		// info data, can be modified (cleaned after call)
);

TCPStream_t * RestoreStateTCPHandler_stream
(
    TCPHandler_t *th,			// valid TCPHandler_t
    RestoreState_t	*rs		// info data, can be modified (cleaned after call)
);

void RestoreStateTCPHandler
(
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    cvp			user_table	// pointer provided by RestoreStateTab_t[]
);

///////////////////////////////////////////////////////////////////////////////

void RestoreStateCommandTCP
(
    RestoreState_t	*rs,		// info data, can be modified (cleaned after call)
    cvp			user_table	// pointer provided by RestoreStateTab_t[]
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			 Linux support			///////////////
///////////////////////////////////////////////////////////////////////////////

#if defined(SYSTEM_LINUX) || defined(__CYGWIN__)
  #include "dclib-network-linux.h"
#endif

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    E N D			///////////////
///////////////////////////////////////////////////////////////////////////////

#endif // DCLIB_NETWORK_H

