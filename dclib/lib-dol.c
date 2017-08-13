
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
 *        Copyright (c) 2012-2017 by Dirk Clemens <wiimm@wiimm.de>         *
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

#define _GNU_SOURCE 1
#include "lib-dol.h"

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    dol header			///////////////
///////////////////////////////////////////////////////////////////////////////

void ntoh_dol_header ( dol_header_t * dest, const dol_header_t * src )
{
    DASSERT(dest);

    if (!src)
	src = dest;
    else if ( dest != src )
	memcpy(dest,src,sizeof(*dest));

    const u32 * src_ptr = src->sect_off;
    u32 * dest_ptr = dest->sect_off;
    u32 * dest_end = (u32*)&dest->padding;

    while ( dest_ptr < dest_end )
	*dest_ptr++ = ntohl(*src_ptr++);
}

///////////////////////////////////////////////////////////////////////////////

void hton_dol_header ( dol_header_t * dest, const dol_header_t * src )
{
    DASSERT(dest);

    if (!src)
	src = dest;
    else if ( dest != src )
	memcpy(dest,src,sizeof(*dest));

    const u32 * src_ptr = src->sect_off;
    u32 * dest_ptr = dest->sect_off;
    u32 * dest_end = (u32*)&dest->padding;

    while ( dest_ptr < dest_end )
	*dest_ptr++ = htonl(*src_ptr++);
}

///////////////////////////////////////////////////////////////////////////////

bool IsDolHeader ( const void *data, uint data_size, uint file_size )
{
    if ( data_size < DOL_HEADER_SIZE )
	return false;

    const dol_header_t *dol = data;
    bool ok = true;
    uint i;
    for ( i = 0; ok && i < DOL_N_SECTIONS; i++ )
    {
	const u32 off  = ntohl(dol->sect_off[i]);
	const u32 size = ntohl(dol->sect_size[i]);
	const u32 addr = ntohl(dol->sect_addr[i]);
	noPRINT("DOL: %8x %8x %08x\n",off,size,addr);
	if ( off || size || addr )
	{
	    if (   off & 3
		|| size & 3
		|| addr & 3
		|| off < DOL_HEADER_SIZE
		|| file_size && off + size > file_size )
	    {
		return false;
	    }
	}
    }
    return true;
}

///////////////////////////////////////////////////////////////////////////////

const char dol_section_name[DOL_NN_SECTIONS+1][4] =
{
    "T0",
    "T1",
    "T2",
    "T3",
    "T4",
    "T5",
    "T6",

    "D0",
    "D1",
    "D2",
    "D3",
    "D4",
    "D5",
    "D6",
    "D7",
    "D8",
    "D9",
    "D10",

    "BSS",
    "ENT",

    ""
};

//
///////////////////////////////////////////////////////////////////////////////
///////////////			advanced interface		///////////////
///////////////////////////////////////////////////////////////////////////////

bool GetDolSectionInfo
(
    dol_sect_info_t	* info,		// valid pointer: returned data
    const dol_header_t	*dol_head,	// valid DOL header
    uint		file_size,	// (file) size of 'data'
    uint		section		// 0 .. DOL_NN_SECTIONS
					//	(7*TEXT, 11*DATA, BSS, ENTRY )
)
{
    DASSERT(dol_head);
    DASSERT(info);
    memset(info,0,sizeof(*info));

    if ( !dol_head || file_size < sizeof(dol_header_t) || section >= DOL_NN_SECTIONS )
    {
	info->section = -1;
	return false;
    }

    info->section = section;
    StringCopyS(info->name,sizeof(info->name),GetDolSectionName(section));

    if ( section < DOL_N_SECTIONS )
    {
	const u32 size = be32(&dol_head->sect_size[section]);
	if (size)
	{
	    info->sect_valid = true;
	    info->size = size;
	    const u32 off  = info->off = be32(&dol_head->sect_off [section]);
	    info->addr = be32(&dol_head->sect_addr[section]);

	    if ( off < file_size && size < file_size && off+size <= file_size )
	    {
		info->data_valid = true;
		info->data =  (u8*)dol_head + off;
	    }
	}
	return true;
    }

    if ( section == DOL_IDX_BSS )
    {
	info->sect_valid = true;
	info->addr = be32(&dol_head->bss_addr);
	info->size = be32(&dol_head->bss_size);
	return true;
    }

    if ( section == DOL_IDX_ENTRY )
    {
	info->sect_valid = true;
	info->addr = be32(&dol_head->entry_addr);
	return true;
    }

    ASSERT(0);
    return false;
}

///////////////////////////////////////////////////////////////////////////////

bool FindFirstFreeDolSection
(
    // returns TRUE on found

    dol_sect_info_t	*info,	// result
    const dol_header_t	*dh,	// DOL header to analyse
    uint		mode	// 0: search all sections (TEXT first)
				// 1: search only TEXT sections
				// 2: search only DATA sections
				// 3: search all sections (DATA first)
)
{
    DASSERT(info);
    DASSERT(dh);

    memset(info,0,sizeof(*info));

    uint idx, end;
    switch (mode)
    {
	case 0:
	    idx = 0;
	    end = DOL_N_SECTIONS;
	    break;

	case 3:
	    if (FindFirstFreeDolSection(info,dh,2))
		return true;
	    // fall through

	case 1:
	    idx = 0;
	    end = DOL_N_TEXT_SECTIONS;
	    break;

	case 2:
	    idx = DOL_N_TEXT_SECTIONS;
	    end = DOL_N_SECTIONS;
	    break;

	default:
	    idx = 0;
	    end = 0;
	    break;
    }

    while ( idx < end && ntohl(dh->sect_size[idx]) )
	idx++;

    if ( idx >= end )
    {
	info->section = -1;
	return false;
    }

    info->section = idx;
    StringCopyS(info->name,sizeof(info->name),GetDolSectionName(idx));
    return true;
}

///////////////////////////////////////////////////////////////////////////////

bool FindDolSectionBySelector
(
    // returns TRUE on found

    dol_sect_info_t		*info,	// result
    const dol_header_t		*dh,	// DOL header to analyse
    const dol_sect_select_t	*dss	// DOL section selector
)
{
    DASSERT(info);
    DASSERT(dh);
    DASSERT(dss);

    if ( dss->sect_idx >= 0 )
    {
	memset(info,0,sizeof(*info));
	info->section = dss->sect_idx;
	memcpy(info->name,dss->name,sizeof(info->name));
	return true;
    }

    return FindFirstFreeDolSection(info,dh,dss->find_mode);
}

///////////////////////////////////////////////////////////////////////////////

u32 FindFreeSpaceDOL
(
    // return address or NULL on not-found

    const dol_header_t	*dol_head,	// valid DOL header
    u32			addr_beg,	// first possible address
    u32			addr_end,	// last possible address
    u32			size,		// minimal size
    u32			align,		// aligning
    u32			*space		// not NULL: store available space here
)
{
    DASSERT(dol_head);

    MemMap_t mm;
    InitializeMemMap(&mm);

    int i;
    for ( i = 0; i < DOL_N_SECTIONS; i++ )
    {
	const u32 size = ntohl(dol_head->sect_size[i]);
	if (size)
	{
	    const u32 addr = ntohl(dol_head->sect_addr[i]);
	    if ( addr < addr_end && addr + size > addr_beg )
	    {
		MemMapItem_t * mi = InsertMemMap(&mm,addr,size);
		if (mi)
		{
		    if ( i < DOL_N_TEXT_SECTIONS )
			snprintf(mi->info,sizeof(mi->info),"T%u",i);
		    else
			snprintf(mi->info,sizeof(mi->info),"D%u",
				i - DOL_N_TEXT_SECTIONS);
		}
	    }
	}
    }
    //PrintMemMap(&mm,stdout,3,"section");

    u64 res_space;
    const u32 res = FindFreeSpaceMemMap(&mm,addr_beg,addr_end,size,align,&res_space);
    ResetMemMap(&mm);
    if (space)
	*space = res_space;
    return res;
}

///////////////////////////////////////////////////////////////////////////////

u32 FindFreeBssSpaceDOL
(
    // return address or NULL on not-found

    const dol_header_t	*dol_head,	// valid DOL header
    u32			size,		// min size
    u32			align,		// aligning
    u32			*space		// not NULL: store available space here
)
{
    DASSERT(dol_head);
    const u32 bss_addr = ntohl(dol_head->bss_addr);
    const u32 bss_size = ntohl(dol_head->bss_size);
    if ( !bss_addr || !bss_size )
    {
	if (space)
	    *space = 0;
	return 0;
    }

    return FindFreeSpaceDOL(dol_head,bss_addr,bss_addr+bss_size,size,align,space);
}

///////////////////////////////////////////////////////////////////////////////
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
)
{
    DASSERT(f);
    DASSERT(dol_head);

    indent = NormalizeIndent(indent);

    dol_header_t dol;
    ntoh_dol_header(&dol,dol_head);

    MemMap_t mm1, mm2, mm3;
    InitializeMemMap(&mm1);
    InitializeMemMap(&mm2);
    InitializeMemMap(&mm3);
    MemMapItem_t * mi = InsertMemMap(&mm1,0,sizeof(dol_header_t));
    StringCopyS(mi->info,sizeof(mi->info),"DOL header");
    if (file_size)
    {
	mi = InsertMemMap(&mm1,file_size,0);
	StringCopyS(mi->info,sizeof(mi->info),"--- end of file ---");
    }

    int i;
    for ( i = 0; i < DOL_N_SECTIONS; i++ )
    {
	const u32 size = dol.sect_size[i];
	if (size)
	{
	    const u32 off  = dol.sect_off[i];
	    const u32 addr = dol.sect_addr[i];

	    char buf[sizeof(mi->info)], buf3[sizeof(mi->info)];
	    if ( i < DOL_N_TEXT_SECTIONS )
	    {
		snprintf(buf,sizeof(buf),"text section T%u",i);
		snprintf(buf3,sizeof(buf3),"%8x : T%u",addr-off,i);
	    }
	    else
	    {
		const int j = i - DOL_N_TEXT_SECTIONS;
		snprintf(buf,sizeof(buf),"data section D%u",j);
		snprintf(buf3,sizeof(buf3),"%8x : D%u",addr-off,j);
	    }

	    mi = InsertMemMap(&mm1,off,size);
	    strcpy(mi->info,buf);
	    mi = InsertMemMap(&mm2,addr,size);
	    strcpy(mi->info,buf);
	    mi = InsertMemMap(&mm3,addr,size);
	    strcpy(mi->info,buf3);
	}
    }

    if ( print_mode & 1 )
    {
	fprintf(f,"%*sMemory map of DOL file:\n\n",indent,"");
	PrintMemMap(&mm1,f,indent+3,"section");
	putc('\n',f);
    }

    if ( print_mode & 2 )
    {
	mi = InsertMemMap(&mm2,dol.bss_addr,dol.bss_size);
	snprintf(mi->info,sizeof(mi->info),"bss section");
	mi = InsertMemMap(&mm2,dol.entry_addr,0);
	snprintf(mi->info,sizeof(mi->info),"entry point");

	fprintf(f,"%*sMemory map of DOL image:\n\n",indent,"");
	mm2.begin = 0xffffffff;
	PrintMemMap(&mm2,f,indent+3,"section");
	putc('\n',f);
    }

    if ( print_mode & 4 )
    {
	mm3.begin = 0xffffffff;
	fprintf(f,"%*sDelta between file offset and virtual address:\n\n",
		    indent,"" );
	PrintMemMap(&mm3,f,indent+3,"   delta : section");
	putc('\n',f);
    }

    ResetMemMap(&mm1);
    ResetMemMap(&mm2);
    ResetMemMap(&mm3);
}

///////////////////////////////////////////////////////////////////////////////

u32 GetDolOffsetByAddr
(
    const dol_header_t	*dol_head,	// valid DOL header
    u32			addr,		// address to search
    u32			size		// >0: return NULL if section is to small
)
{
    DASSERT(dol_head);

    int sect;
    for ( sect = 0; sect < DOL_N_SECTIONS; sect++ )
    {
	const u32 sect_addr = ntohl(dol_head->sect_addr[sect]);
	const u32 sect_size = ntohl(dol_head->sect_size[sect]);
	if ( addr >= sect_addr && addr + size <= sect_addr + sect_size )
	    return ntohl(dol_head->sect_off[sect]) + addr - sect_addr;
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////

u32 GetDolAddrByOffset
(
    const dol_header_t	*dol_head,	// valid DOL header
    u32			off,		// address to search
    u32			size		// >0: return NULL if section is to small
)
{
    DASSERT(dol_head);

    int sect;
    for ( sect = 0; sect < DOL_N_SECTIONS; sect++ )
    {
	const u32 sect_off  = ntohl(dol_head->sect_off[sect]);
	const u32 sect_size = ntohl(dol_head->sect_size[sect]);
	if ( off >= sect_off && off + size <= sect_off + sect_size )
	    return ntohl(dol_head->sect_addr[sect]) + off - sect_off;
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////

uint CountOverlappedDolSections
(
    // returns the number of overlapped section by [addr,size]

    const dol_header_t	*dol_head,	// valid DOL header
    u32			addr,		// address to search
    u32			size		// size of addr to verify
)
{
    DASSERT(dol_head);

    u32 end = addr + size;
    if ( end < addr ) // overflow
	end = M1(end);

    uint sect, count = 0;
    for ( sect = 0; sect < DOL_N_SECTIONS; sect++ )
    {
	const u32 sect_addr = ntohl(dol_head->sect_addr[sect]);
	const u32 sect_size = ntohl(dol_head->sect_size[sect]);
	if ( addr < sect_addr + sect_size && end > sect_addr )
	    count++;

	noPRINT("%8x..%8x / %8x..%8x => %d/%u\n",
	    addr, end, sect_addr, sect_addr + sect_size,
	    addr < sect_addr + sect_size && end > sect_addr, count );
    }
    return count;
}

///////////////////////////////////////////////////////////////////////////////

#ifdef __APPLE__
 void * memmem ( const void *l, size_t l_len, const void *s, size_t s_len );
#endif // __APPLE__

///////////////////////////////////////////////////////////////////////////////

static u32 FindDolAddress
(
    const u8	*data,		// DOL data beginning with dol_header_t
    uint	off_begin,	// begin search here
    uint	off_end,	// end search here
    const u8	*search,	// data to search
    uint	serach_size	// size of 'search'
)
{
    while ( off_begin < off_end )
    {
	const u8 *res
	    = memmem( data+off_begin, off_end-off_begin, search, serach_size );
	if (!res)
	    return 0;
	off_begin = res - data;
	if (!(off_begin&3)) // check alignment
	    return off_begin;
	off_begin++;
    }
    return 0;
}

//-----------------------------------------------------------------------------

u32 FindDolAddressOfVBI
(
    // search in available data and return NULL if not found

    cvp			data,		// DOL data beginning with dol_header_t
    uint		data_size	// size of 'data'
)
{
    if ( data_size < sizeof(dol_header_t) )
	return 0;
    const dol_header_t *dh = (dol_header_t*)data;

    static const u8 search1[] = { 0x7C,0xE3,0x3B,0x78, 0x38,0x87,0x00,0x34,
				  0x38,0xA7,0x00,0x38, 0x38,0xC7,0x00,0x4C };
    static const u8 search2[] = { 0x4E,0x80,0x00,0x20 };

    int sect;
    for ( sect = 0; sect < DOL_N_SECTIONS; sect++ )
    {
	const u32 off1 = ntohl(dh->sect_off[sect]);
	const u32 size = ntohl(dh->sect_size[sect]);
	if ( !size || off1 >= data_size )
	    continue;

	u32 off_end = off1 + size;
	if ( off_end > data_size )
	    off_end = data_size;

	u32 off2 = FindDolAddress( data, off1, off_end, search1, sizeof(search1) );
	if (off2)
	{
	    off2 = FindDolAddress( data, off2+sizeof(search1), off_end,
				search2, sizeof(search2) );
	    if (off2)
		return ntohl(dh->sect_addr[sect]) + off2 - off1;
	}
    }
    return 0;
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////			Gecko Code Handler		///////////////
///////////////////////////////////////////////////////////////////////////////

bool IsValidGCH
(
    const gch_header_t *gh,		// valid header
    uint		file_size	// size of file
)
{
    DASSERT(gh);

    if ( file_size < sizeof(*gh) || ntohl(gh->magic) != GCH_MAGIC_NUM )
	return false;

    const u32 addr  = ntohl(gh->addr);
    const u32 size  = ntohl(gh->size);
    const u32 entry = ntohl(gh->vbi_entry);

    if ( addr < 0x80000000 || sizeof(*gh) + size > file_size )
	return false;

    if ( entry && ( entry < addr || entry >= addr + size - 4 ))
	return false;

    return true;
}

///////////////////////////////////////////////////////////////////////////////

ccp DecodeWCH
(
    // returns NULL on success, or a short error message

    wch_control_t	*wc,		// store only, (initialized)
    void		*data,		// source data, modified if type != 0
    uint		size,		// size of 'data'
    DecompressWCH_func	decompress	// NULL or decompression function
)
{
    DASSERT(wc);
    DASSERT( data || !size );

    memset(wc,0,sizeof(*wc));
    if ( !data || size < sizeof(wch_header_t) + sizeof(wch_segment_t) )
	return "To small for a WCH file";

    const wch_header_t *wh = data;
    wc->wh.magic   = ntohl(wh->magic);
    wc->wh.version = ntohl(wh->version);
    wc->wh.size	   = ntohl(wh->size);
    if ( wc->wh.magic != WCH_MAGIC_NUM || wc->wh.version > 1 )
	return "Illegal WCH header";

    const wch_segment_t *ptr = wh->segment;
    if ( wc->wh.version == 1 && decompress )
    {
	wc->temp_size = wc->wh.size;
	wc->temp_data = MALLOC(wc->temp_size);
	DASSERT(wc->temp_data);

	uint data_size = size - sizeof(wch_header_t);
	if ( decompress(wc,(void*)ptr,data_size) != ERR_OK )
	    return "Decompression of WCH failed.";
	ptr = (wch_segment_t*)wc->temp_data;
    }

    const wch_segment_t *end = (wch_segment_t*)( (u8*)ptr + wc->wh.size );
    noPRINT("%p %p [%zd]\n",ptr,end,(u8*)end-(u8*)ptr);

    uint iseg;
    wch_segment_t *dseg = wc->seg;
    for ( iseg = 0; iseg < WCH_MAX_SEG; iseg++, dseg++ )
    {
	if (!ptr->type)
	    break;
	dseg->type		= ntohl(ptr->type);
	dseg->addr		= ntohl(ptr->addr);
	dseg->size		= ntohl(ptr->size);
	dseg->main_entry	= ntohl(ptr->main_entry);
	dseg->main_entry_old	= ntohl(ptr->main_entry_old);
	dseg->vbi_entry		= ntohl(ptr->vbi_entry);
	dseg->vbi_entry_old	= ntohl(ptr->vbi_entry_old);

	u8 *src_data = (u8*)ptr->data;
	wc->seg_data[iseg] = src_data;
	ptr = (wch_segment_t*)(ptr->data + ALIGN32(dseg->size,4));
	if ( ptr > end )
	{
	    wc->is_valid = false;
	    return "Damaged WCH data";
	}
    }
    wc->n_seg = iseg;
    memset(dseg,0,sizeof(*dseg));
    wc->is_valid = true;
    return 0;
}

///////////////////////////////////////////////////////////////////////////////

void ResetWCH ( wch_control_t * wc )
{
    if ( wc && wc->temp_data )
    {
	FREE(wc->temp_data);
	wc->temp_data = 0;
	wc->temp_size = 0;
    }
}

//
///////////////////////////////////////////////////////////////////////////////
///////////////			    E N D			///////////////
///////////////////////////////////////////////////////////////////////////////
