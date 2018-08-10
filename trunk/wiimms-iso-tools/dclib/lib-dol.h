
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

#ifndef DC_LIB_DOL_H
#define DC_LIB_DOL_H 1

#define _GNU_SOURCE 1
#include "dclib-basics.h"

//
///////////////////////////////////////////////////////////////////////////////
///////////////			DOL: defs & structs		///////////////
///////////////////////////////////////////////////////////////////////////////

#define DOL_N_TEXT_SECTIONS	 7
#define DOL_N_DATA_SECTIONS	11
#define DOL_N_SECTIONS		18

#define DOL_IDX_BSS		DOL_N_SECTIONS		// alias for BSS
#define DOL_IDX_ENTRY		(DOL_N_SECTIONS+1)	// alias for ENTRY
#define DOL_NN_SECTIONS		(DOL_N_SECTIONS+2)	// N + aliase

#define DOL_HEADER_SIZE		0x100

//-----------------------------------------------------------------------------

static int IsDolTextSection ( uint section )
	{ return section < DOL_N_TEXT_SECTIONS; }

static bool IsDolDataSection ( uint section )
	{ return section - DOL_N_TEXT_SECTIONS < DOL_N_DATA_SECTIONS; }

//-----------------------------------------------------------------------------
// [[dol_header_t]]

typedef struct dol_header_t
{
    /* 0x00 */	u32 sect_off [DOL_N_SECTIONS];	// file offset
    /* 0x48 */	u32 sect_addr[DOL_N_SECTIONS];	// virtual address
    /* 0x90 */	u32 sect_size[DOL_N_SECTIONS];	// section size
    /* 0xd8 */	u32 bss_addr;			// BSS address
    /* 0xdc */	u32 bss_size;			// BSS size
    /* 0xe0 */	u32 entry_addr;			// entry point
    /* 0xe4 */	u8  padding[DOL_HEADER_SIZE-0xe4];
}
__attribute__ ((packed)) dol_header_t;

///////////////////////////////////////////////////////////////////////////////
// [[dol_sect_info_t]]

typedef struct dol_sect_info_t
{
    int		section;	// section index, <0: invalid
    char	name[4];	// name of section
    u32		off;		// file offset of data
    u32		addr;		// image address
    u32		size;		// size of section
    bool	sect_valid;	// true: section is valid
    bool	data_valid;	// true: data is valid (size>0 and inside DOL file)
    bool	hash_valid;	// true: 'hash' is valid
    u8		*data;		// NULL (data_valid=0) or pointer to data (data_valid=1)
    sha1_hash_t	hash;		// SHA1 hash of data
}
dol_sect_info_t;

///////////////////////////////////////////////////////////////////////////////
// [[dol_sect_select_t]]

typedef struct dol_sect_select_t
{
    int		find_mode;	// mode for xFindFirstFreeDolSection(), <0: skip this
    int		sect_idx;	// >=0: section, <0: auto select
    char	name[4];	// a name based on 'sect_idx' and 'find_mode'
    u32		addr;		// address of section, if 0: use DATA[0x10]
    ccp		fname;		// file name
    bool	use_param;	// true: write params (entry and '.dol' section)

    u8		*data;		// not NULL: data, alloced
    uint	size;		// >0: size of 'data'
    u32		offset;		// last used file offset (temporary)
}
dol_sect_select_t;

//
///////////////////////////////////////////////////////////////////////////////
///////////////			DOL: Interface			///////////////
///////////////////////////////////////////////////////////////////////////////

void ntoh_dol_header ( dol_header_t * dest, const dol_header_t * src );
void hton_dol_header ( dol_header_t * dest, const dol_header_t * src );
bool IsDolHeader ( const void *data, uint data_size, uint file_size );

extern const char dol_section_name[DOL_NN_SECTIONS+1][4];
static inline ccp GetDolSectionName ( uint section )
{
    return section < DOL_NN_SECTIONS ? dol_section_name[section] : 0;
}

///////////////////////////////////////////////////////////////////////////////

bool GetDolSectionInfo
(
    dol_sect_info_t	* ret_info,	// valid pointer: returned data
    const dol_header_t	*dol_head,	// valid DOL header
    uint		file_size,	// (file) size of 'data'
    uint		section		// 0 .. DOL_NN_SECTIONS
					//	(7*TEXT, 11*DATA, BSS, ENTRY )
);

//-----------------------------------------------------------------------------

bool FindFirstFreeDolSection
(
    // returns TRUE on found

    dol_sect_info_t	*info,	// result
    const dol_header_t	*dh,	// DOL header to analyse
    uint		mode	// 0: search all sections (TEXT first)
				// 1: search only TEXT sections
				// 2: search only DATA sections
				// 3: search all sections (DATA first)
);

//-----------------------------------------------------------------------------

bool FindDolSectionBySelector
(
    // returns TRUE on found

    dol_sect_info_t		*info,	// result
    const dol_header_t		*dh,	// DOL header to analyse
    const dol_sect_select_t	*dss	// DOL section selector
);

//-----------------------------------------------------------------------------

u32 FindFreeSpaceDOL
(
    // return address or NULL on not-found

    const dol_header_t	*dol_head,	// valid DOL header
    u32			addr_beg,	// first possible address
    u32			addr_end,	// last possible address
    u32			size,		// minimal size
    u32			align,		// aligning
    u32			*space		// not NULL: store available space here
);

//-----------------------------------------------------------------------------

u32 FindFreeBssSpaceDOL
(
    // return address or NULL on not-found

    const dol_header_t	*dol_head,	// valid DOL header
    u32			size,		// min size
    u32			align,		// aligning
    u32			*space		// not NULL: store available space here
);

///////////////////////////////////////////////////////////////////////////////

void DumpDolHeader
(
    FILE		* f,		// dump to this file
    int			indent,		// indention
    const dol_header_t	*dol_head,	// valid DOL header
    uint		file_size,	// NULL or size of file
    uint		print_mode	// bit field:
					//  1: print file map
					//  2: print virtual mem map
					//  4: print delta table
);

///////////////////////////////////////////////////////////////////////////////

u32 GetDolOffsetByAddr
(
    const dol_header_t	*dol_head,	// valid DOL header
    u32			addr,		// address to search
    u32			size		// >0: return NULL if section is to small
);

///////////////////////////////////////////////////////////////////////////////

u32 GetDolAddrByOffset
(
    const dol_header_t	*dol_head,	// valid DOL header
    u32			off,		// address to search
    u32			size		// >0: return NULL if section is to small
);

///////////////////////////////////////////////////////////////////////////////

uint CountOverlappedDolSections
(
    // returns the number of overlapped section by [addr,size]

    const dol_header_t	*dol_head,	// valid DOL header
    u32			addr,		// address to search
    u32			size		// size of addr to verify
);

///////////////////////////////////////////////////////////////////////////////

u32 FindDolAddressOfVBI
(
    // search in available data and return NULL if not found

    cvp			data,		// DOL data beginning with dol_header_t
    uint		data_size	// size of 'data'
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			Gecko Code Handler		///////////////
///////////////////////////////////////////////////////////////////////////////

#define GCH_MAGIC_NUM 0x47044348

#define GCT_MAGIC_NUM	0x00d0c0de00d0c0deull
#define GCT_TERM_NUM	0xf000000000000000ull
#define GCT_SEP_NUM1	0xf0000001u
#define GCT_REG_OFFSET	8

///////////////////////////////////////////////////////////////////////////////
// [[gch_header_t]]

typedef struct gch_header_t
{
    // big endian!

    u32	magic;			// magic: 'G\x{04}CH' (Gecko Code Handler)
    u32	addr;			// address of new section
    u32	size;			// size of code section, file size must be >= 'size'
				// a cheat section may follow
    u32	vbi_entry;		// >0: entry point for VBI interrupts

    u8  data[];			// usually start of code handler
}
__attribute__ ((packed)) gch_header_t;

///////////////////////////////////////////////////////////////////////////////

bool IsValidGCH
(
    const gch_header_t *gh,		// valid header
    uint		file_size	// size of file
);

//
///////////////////////////////////////////////////////////////////////////////
///////////////			Wiimms Code Handler		///////////////
///////////////////////////////////////////////////////////////////////////////

#define WCH_MAGIC_NUM 0x57054348

///////////////////////////////////////////////////////////////////////////////
// [[wch_segment_t]]

typedef struct wch_segment_t
{
    // big endian!

    u32 type;			// 'T': text section
				// 'D': data section
				// 'S': any section, try data first, then text
				// 'P': patch data => patch main.dol
				//  0 : end of segment list

    u32 addr;			// address, where the data is stored
    u32 size;			// size of data

    u32	main_entry;		// >0: `main entry point´
    u32	main_entry_old;		// >0: store old `main entry point´ at this address
    u32	vbi_entry;		// >0: `vbi entry point´
    u32	vbi_entry_old;		// >0: store old `vbi entry point´ at this address

    u8 data[];			// data, aligned by ALIGN(size,4)
    // wch_segment_t		// next segment, aligned by ALIGN(size,4)
}
__attribute__ ((packed)) wch_segment_t;

///////////////////////////////////////////////////////////////////////////////
// [[wch_header_t]]

typedef struct wch_header_t
{
    // big endian!

    u32	magic;			// magic: 'W\x{05}CH' (Gecko Code Handler)
    u32 version;		// 0: raw, 1: bzip2
    u32	size;			// total size of (uncompressed) segment data

    wch_segment_t segment[];	// first segment
}
__attribute__ ((packed)) wch_header_t;

///////////////////////////////////////////////////////////////////////////////
// [[wch_control_t]]

#define WCH_MAX_SEG 50

typedef struct wch_control_t
{
    u8			*temp_data;	// not NULL: temporary data, alloced
    uint		temp_size;	// not NULL: size of 'temp_data'

    bool		is_valid;	// true: data is valid
    wch_header_t	wh;		// decoded header, local endian

    uint		n_seg;		// number of segments excluding terminator
    wch_segment_t seg[WCH_MAX_SEG+1];	// decoded segment headers, local endian
					//  + special terminator segment (type==0)
    u8 *seg_data[WCH_MAX_SEG+1];	// pointer to decoded data for each segment
}
wch_control_t;

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

typedef enumError (*DecompressWCH_func)
(
    // return TRUE on success

    wch_control_t	*wc,		// valid data, includes type info
    void		*data,		// source data to decompress
    uint		size		// size of 'data'
);

///////////////////////////////////////////////////////////////////////////////

ccp DecodeWCH
(
    // returns NULL on success, or a short error message

    wch_control_t	*wc,		// store only, (initialized)
    void		*data,		// source data, modified if type != 0
    uint		size,		// size of 'data'
    DecompressWCH_func	decompress	// NULL or decompression function
);

void ResetWCH ( wch_control_t * wc );

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    E N D			///////////////
///////////////////////////////////////////////////////////////////////////////

#endif // DC_LIB_DOL_H 1
