/* Decodes LSDAs the way the GNU C++ personality routine does, for comparison
   with the lsda crate (tests/oracle.rs).

   Pointers are read by libgcc's unwind-pe.h, which build.sh downloads from
   GCC and changes in one place only: indirect pointers are not followed.
   The functions marked below are transcribed from
   libstdc++-v3/libsupc++/eh_personality.cc (GCC 14.2), with the type
   matching replaced by printing what would be matched. GCC is licensed
   under the GPL v3 with the GCC Runtime Library Exception; this file is a
   test tool and is not part of the published crate.

   The width of the host's pointers is the address size: build a 32-bit
   oracle for 32-bit LSDAs. The host must be little-endian.

   Input on stdin, repeated until the end:
     u8  unwinder (0 DWARF, 1 Arm EHABI, 2 SJLJ)
     u32 section length, then the section
     u32 offset of the LSDA in the section
     u32 number of locations, then each as a u64: an offset from the
         function start (DWARF, Arm EHABI) or a 1-based call-site index (SJLJ)

   Output, for each case, in the format the test produces from the crate:
     hdr <LPStart> <@TType encoding> <@TType base | -> <call-site encoding>
         <action table>
     loc <location> -                  (no call site: terminate)
     loc <location> <landing pad> <first action | ->
     rec <action> <filter> <next action | ->
     type <type_info>                  (catch)
     spec <index> <type_info>          (exception specification entry)
     word <TARGET2 word>               (Arm EHABI exception specification entry)
     end
   Numbers are hexadecimal, except filters. Section offsets stand for
   addresses: pc-relative values are relative to the section start. */

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEXT_BASE 0x1000
#define DATA_BASE 0x200000
#define FUNCTION_START 0

/* Base addresses for unwind-pe.h, which gets them from the context. */
#define _Unwind_GetTextRelBase oracle_text_base
#define _Unwind_GetDataRelBase oracle_data_base
#define _Unwind_GetRegionStart oracle_region_start
#include <unwind.h>

_Unwind_Ptr oracle_text_base (struct _Unwind_Context *c) { (void) c; return TEXT_BASE; }
_Unwind_Ptr oracle_data_base (struct _Unwind_Context *c) { (void) c; return DATA_BASE; }
_Unwind_Ptr oracle_region_start (struct _Unwind_Context *c) { (void) c; return FUNCTION_START; }

/* Report aborts and stray reads instead of dying, so that the other cases
   are still compared. */
static sigjmp_buf failed;
static void __attribute__ ((noreturn)) oracle_abort (void) { siglongjmp (failed, 1); }
static void on_signal (int sig) { (void) sig; siglongjmp (failed, 2); }
#define abort oracle_abort

/* build.sh replaces the dereference of indirect pointers with this. */
static _Unwind_Internal_Ptr oracle_indirect (_Unwind_Internal_Ptr p) { return p; }

#include "unwind-pe.h"

static const unsigned char *section;
static unsigned char unwinder;
static struct _Unwind_Context *context
  = (struct _Unwind_Context *) &section; /* Any non-null pointer. */

/* Express an address read in ENCODING relative to the section start, if it
   is pc-relative. libgcc leaves null values alone. */
static unsigned long long
norm (unsigned char encoding, _Unwind_Ptr value)
{
  if (encoding != DW_EH_PE_omit && encoding != DW_EH_PE_aligned
      && (encoding & 0x70) == DW_EH_PE_pcrel && value != 0)
    value -= (_Unwind_Ptr) section;
  return value;
}

static unsigned long long
off (const unsigned char *p)
{
  return (unsigned long long) (p - section);
}

/* --- From eh_personality.cc. --- */

struct lsda_header_info
{
  _Unwind_Ptr Start;
  _Unwind_Ptr LPStart;
  _Unwind_Ptr ttype_base;
  const unsigned char *TType;
  const unsigned char *action_table;
  unsigned char ttype_encoding;
  unsigned char call_site_encoding;
};

static unsigned char lpstart_encoding_seen;

static const unsigned char *
parse_lsda_header (struct _Unwind_Context *context, const unsigned char *p,
		   struct lsda_header_info *info)
{
  _uleb128_t tmp;
  unsigned char lpstart_encoding;

  info->Start = (context ? _Unwind_GetRegionStart (context) : 0);

  // Find @LPStart, the base to which landing pad offsets are relative.
  lpstart_encoding = *p++;
  lpstart_encoding_seen = lpstart_encoding;
  if (lpstart_encoding != DW_EH_PE_omit)
    p = read_encoded_value (context, lpstart_encoding, p, &info->LPStart);
  else
    info->LPStart = info->Start;

  // Find @TType, the base of the handler and exception spec type data.
  info->ttype_encoding = *p++;
  if (info->ttype_encoding != DW_EH_PE_omit)
    {
      p = read_uleb128 (p, &tmp);
      info->TType = p + tmp;
    }
  else
    info->TType = 0;

  // The encoding and length of the call-site table; the action table
  // immediately follows.
  info->call_site_encoding = *p++;
  p = read_uleb128 (p, &tmp);
  info->action_table = p + tmp;

  return p;
}

// Return an element from a type table.
static _Unwind_Ptr
get_ttype_entry (struct lsda_header_info *info, _uleb128_t i)
{
  _Unwind_Ptr ptr;

  i *= size_of_encoded_value (info->ttype_encoding);
  read_encoded_value_with_base (info->ttype_encoding, info->ttype_base,
				info->TType - i, &ptr);

  return ptr;
}

/* Print a catch type. For the Arm EHABI, libstdc++ overrides the @TType
   encoding with a platform-specific one, and libc++abi ignores it: both read
   word-sized R_ARM_TARGET2 values, printed raw. */
static void
print_type (struct lsda_header_info *info, _uleb128_t i)
{
  if (unwinder == 1)
    printf ("type %llx\n",
	    (unsigned long long) *(const uint32_t *) (info->TType - i * 4));
  else
    printf ("type %llx\n",
	    norm (info->ttype_encoding, get_ttype_entry (info, i)));
}

// The list walk of check_exception_spec.
static void
print_exception_spec (struct lsda_header_info *info, _sleb128_t filter_value)
{
  if (unwinder == 1)
    {
      // The Arm EHABI lists R_ARM_TARGET2 words.
      const uint32_t *e = ((const uint32_t *) info->TType) - filter_value - 1;
      while (1)
	{
	  uint32_t tmp = *e;
	  if (tmp == 0)
	    return;
	  printf ("word %llx\n", (unsigned long long) tmp);
	  e++;
	}
    }
  else
    {
      const unsigned char *e = info->TType - filter_value - 1;
      while (1)
	{
	  _uleb128_t tmp;
	  e = read_uleb128 (e, &tmp);
	  // Zero signals the end of the list.
	  if (tmp == 0)
	    return;
	  printf ("spec %llx %llx\n", (unsigned long long) tmp,
		  norm (info->ttype_encoding, get_ttype_entry (info, tmp)));
	}
    }
}

/* The call-site search and the action walk of the personality routine. */
static void
search (const unsigned char *language_specific_data, _Unwind_Ptr ip)
{
  struct lsda_header_info info;
  const unsigned char *action_record;
  const unsigned char *p;
  _Unwind_Ptr landing_pad;

  p = parse_lsda_header (context, language_specific_data, &info);
  info.ttype_base = base_of_encoded_value (info.ttype_encoding, context);
  landing_pad = 0;
  action_record = 0;

  printf ("loc %llx ", (unsigned long long) ip);
  if (unwinder == 2)
    {
      // The given "IP" is an index into the call-site table.
      _uleb128_t cs_lp, cs_action;
      do
	{
	  p = read_uleb128 (p, &cs_lp);
	  p = read_uleb128 (p, &cs_action);
	}
      while (--ip);

      landing_pad = cs_lp + 1;
      if (cs_action)
	action_record = info.action_table + cs_action - 1;
      // The landing pad is a dispatch index; print it as recorded.
      landing_pad -= 1;
      goto found_something;
    }

  // Search the call-site table for the action associated with this IP.
  ip += info.Start;
  while (p < info.action_table)
    {
      _Unwind_Ptr cs_start, cs_len, cs_lp;
      _uleb128_t cs_action;

      // Note that all call-site encodings are "absolute" displacements.
      p = read_encoded_value (0, info.call_site_encoding, p, &cs_start);
      p = read_encoded_value (0, info.call_site_encoding, p, &cs_len);
      p = read_encoded_value (0, info.call_site_encoding, p, &cs_lp);
      p = read_uleb128 (p, &cs_action);

      // The table is sorted, so if we've passed the ip, stop.
      if (ip < info.Start + cs_start)
	p = info.action_table;
      else if (ip < info.Start + cs_start + cs_len)
	{
	  if (cs_lp)
	    landing_pad = norm (lpstart_encoding_seen, info.LPStart) + cs_lp;
	  if (cs_action)
	    action_record = info.action_table + cs_action - 1;
	  goto found_something;
	}
    }

  // If ip is not present in the table, call terminate.
  printf ("-\n");
  return;

 found_something:
  printf ("%llx ", (unsigned long long) landing_pad);
  if (action_record == 0)
    {
      printf ("-\n");
      return;
    }
  printf ("%llx\n", off (action_record));

  // The personality routine stops at a matching handler; print them all.
  for (int records = 0; records < 1000; records++)
    {
      _sleb128_t ar_filter, ar_disp;

      p = action_record;
      p = read_sleb128 (p, &ar_filter);
      read_sleb128 (p, &ar_disp);

      printf ("rec %llx %lld ", off (action_record), (long long) ar_filter);
      if (ar_disp == 0)
	printf ("-\n");
      else
	printf ("%llx\n", off (p + ar_disp));

      if (ar_filter > 0)
	print_type (&info, ar_filter);
      else if (ar_filter < 0)
	print_exception_spec (&info, ar_filter);

      if (ar_disp == 0)
	break;
      action_record = p + ar_disp;
    }
}

/* --- End of eh_personality.cc. --- */

static void
header (const unsigned char *lsda)
{
  struct lsda_header_info info;
  parse_lsda_header (context, lsda, &info);
  printf ("hdr %llx %02x ", norm (lpstart_encoding_seen, info.LPStart),
	  info.ttype_encoding);
  if (info.TType)
    printf ("%llx ", off (info.TType));
  else
    printf ("- ");
  printf ("%02x %llx\n", info.call_site_encoding, off (info.action_table));
}

static void
read_exact (void *buf, size_t len)
{
  if (fread (buf, 1, len, stdin) != len)
    {
      fprintf (stderr, "oracle: truncated input\n");
      exit (2);
    }
}

int
main (void)
{
  /* Room for reads past the end of a section, which the comparison flags. */
  enum { GUARD = 4096 };
  struct sigaction sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = on_signal;
  sigaction (SIGSEGV, &sa, NULL);
  sigaction (SIGBUS, &sa, NULL);

  for (;;)
    {
      uint32_t len, lsda_offset, count;
      int c = getchar ();
      if (c == EOF)
	break;
      unwinder = (unsigned char) c;
      read_exact (&len, 4);
      /* malloc aligns the section, as DW_EH_PE_aligned assumes. */
      unsigned char *data = calloc (1, (size_t) len + GUARD);
      if (!data)
	return 2;
      read_exact (data, len);
      read_exact (&lsda_offset, 4);
      read_exact (&count, 4);
      uint64_t *locations = calloc (count + 1, sizeof (uint64_t));
      if (!locations)
	return 2;
      read_exact (locations, (size_t) count * 8);

      section = data;
      if (sigsetjmp (failed, 1) == 0)
	{
	  header (data + lsda_offset);
	  for (uint32_t i = 0; i < count; i++)
	    search (data + lsda_offset, (_Unwind_Ptr) locations[i]);
	}
      else
	printf ("failed\n");
      printf ("end\n");
      fflush (stdout);
      free (locations);
      free (data);
    }
  return 0;
}
