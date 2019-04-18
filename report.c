#ifndef DISABLE_HTTP_DASHBOARD
#include <stdbool.h>
#include <search.h>
#include <unistd.h>
#include <glib.h>
#include <sched.h>
#include <stdio.h>
#include <ClearSilver.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "sysfuzz.h"
#include "typelib.h"
#include "iknowthis.h"

// This routine adds some global error statistics to the HDF tree, as well as
// calculating the total number of tests executed and total number of fuzzers
// currently enabled.
static void generate_global_statistics(HDF *hdf)
{
    const gint   MaxErrnoValue = 1024;
    HDF         *errors        = NULL;
    guint        total         = 0;
    guint        failures      = 0;
    guint        successes     = 0;
    guint        fuzzercount   = 0;

    // Create the Global Errors heirarchy.
    hdf_set_value(hdf, "Global.errors", NULL);

    // Retrieve that object.
    errors = hdf_get_obj(hdf, "Global.errors");

    // Quick compare callback for lfind().
    gint compare_error(gconstpointer a, gconstpointer b)
    {
        return ((const error_record_t *)(a))->error
            -  ((const error_record_t *)(b))->error;
    }

    // For every errno code possible, count how many times each fuzzer has seen
    // it. This is obviously not optimal, but this is not a performance
    // critical lookup.
    for (guint code = 0; code < MaxErrnoValue; code++) {
        error_record_t  *error = NULL;
        error_record_t   key   = { code, 0 };
        guint            count = 0;

        // For every system call, check if it has this errno.
        for (guint sysno = 0; sysno < MAX_SYSCALL_NUM; sysno++) {

            // Retrieve pointer to this fuzzer.
            syscall_fuzzer_t *fuzzer = &system_call_fuzzers[sysno];

            // Sanity checks.
            g_assert_cmpuint(fuzzer->numerrors, <, MAX_ERROR_CODES);

            // Search it's errors structure for this errno.
            error = lfind(&key,                   // key
                          fuzzer->errors,         // base
                          &fuzzer->numerrors,     // num
                          sizeof key,             // size
                          compare_error);         // compare

            // If there was a hit, add it to the count.
            if (error) {
                count += error->count;
            }

            // Keep track of statistics, only for the first iteration.
            if (code == 0) {
                total       += fuzzer->total;
                failures    += fuzzer->failures;
                successes   += fuzzer->total - fuzzer->failures;

                // Count the fuzzers that are enabled.
                if (fuzzer->name && !(fuzzer->flags & SYS_DISABLED)) {
                    fuzzercount++;
                }
            }
        }

        // Add the final count to the data if it was non-zero.
        if (count) {
            gchar *nodedesc  = g_strdup_printf("%u.description", code);
            gchar *nodecount = g_strdup_printf("%u.count", code);

            hdf_set_value(errors, nodedesc, custom_strerror_wrapper(code));
            hdf_set_int_value(errors, nodecount, count);

            // Clean up.
            g_free(nodedesc);
            g_free(nodecount);
        }
    }

    // Add some global statistics.
    hdf_set_int_value(hdf, "Global.num_fuzzers", fuzzercount);
    hdf_set_int_value(hdf, "Global.total_executions", total);
    hdf_set_int_value(hdf, "Global.total_failures", failures);
    hdf_set_int_value(hdf, "Global.total_successes", successes);

    return;
}


// This routine scans the list of fuzzers for best and worst performers, and
// adds an appropriate node to the HDF.
static void generate_fuzzer_statistics(HDF *hdf)
{
    syscall_fuzzer_t    *fastest = NULL;
    syscall_fuzzer_t    *slowest = NULL;

    // For every system call, collect statistics.
    for (guint sysno = 0; sysno < MAX_SYSCALL_NUM; sysno++) {

        // Retrieve pointer to this fuzzer.
        syscall_fuzzer_t *fuzzer = &system_call_fuzzers[sysno];

        if (!fuzzer->name || (fuzzer->flags & SYS_DISABLED))
            continue;

        // Compare statistics.
        if (!fastest || fuzzer->average < fastest->average)
            fastest = fuzzer;
        if (!slowest || fuzzer->average > slowest->average)
            slowest = fuzzer;
    }

    // Check we have a result
    if (fastest == NULL || slowest == NULL) {
        g_warning("statistics generation may fail, there do not appear to be any fuzzers enabled");
        return;
    }

    hdf_set_value(hdf, "Global.fastest_fuzzer.name", fastest->name);
    hdf_set_int_value(hdf, "Global.fastest_fuzzer.speed", fastest->average * 1000000);

    hdf_set_value(hdf, "Global.slowest_fuzzer.name", slowest->name);
    hdf_set_int_value(hdf, "Global.slowest_fuzzer.speed", slowest->average * 1000000);

    return;
}

// This routine adds lots of details about this specific fuzzer to the HDF.
void pretty_print_fuzzer(HDF *hdf, syscall_fuzzer_t *fuzzer)
{
    gchar   *name          = g_strdup_printf("Fuzzer.%u", fuzzer->number);
    HDF     *info          = NULL;

    // Create an heirarchy for this fuzzer
    hdf_set_value(hdf, name, NULL);

    // Retrieve that object.
    info = hdf_get_obj(hdf, name);

    hdf_set_value(info, "Name", fuzzer->name);
    hdf_set_int_value(info, "Total", fuzzer->total);
    hdf_set_int_value(info, "Failures", fuzzer->failures);
    hdf_set_int_value(info, "NumErrors", fuzzer->numerrors);
    hdf_set_value(info, "Errors", NULL);

    // Now switch to error tree.
    info = hdf_get_obj(info, "Errors");

    // Enumerate all the errors this fuzzer has seen.
    for (gint i = 0; i < fuzzer->numerrors; i++) {
        gchar *error = g_strdup_printf("%u.error", i);
        gchar *count = g_strdup_printf("%u.count", i);

        hdf_set_value(info, error, custom_strerror_wrapper(fuzzer->errors[i].error));
        hdf_set_int_value(info, count, fuzzer->errors[i].count);

        g_free(error);
        g_free(count);
    }

    g_free(name);
    return;
}

void create_fuzzer_report(HDF *hdf)
{
    // First create the global error statistics.
    generate_global_statistics(hdf);

    // Get some overall fuzzer stats (Slowest, Fastest, etc.)
    generate_fuzzer_statistics(hdf);

    // Create some empty hdf nodes.
    hdf_set_value(hdf, "Global.fuzzer_missing", NULL);        // Not defined
    hdf_set_value(hdf, "Global.fuzzer_disabled", NULL);       // Defined but disabled
    hdf_set_value(hdf, "Global.fuzzer_always_fails", NULL);   // Always fail, but not marked SYS_FAIL.
    hdf_set_value(hdf, "Global.fuzzer_always_same", NULL);    // Always return the same value, but not marked SYS_BORING.
    hdf_set_value(hdf, "Global.fuzzer_not_boring", NULL);     // Marked SYS_BORING, but returning multiple values.

    // Now we need to create a list of interesting events the user needs to
    // investigate. The first one is system calls that have no associated
    // fuzzers, so scan the list for fuzzers with NULL callback.

    for (guint i = 0; i < MAX_SYSCALL_NUM; i++) {
        // Is the system call undefined?
        if (system_call_fuzzers[i].callback == NULL) {
            gchar   *node = g_strdup_printf("%u.number", i);
            hdf_set_int_value(hdf_get_obj(hdf, "Global.fuzzer_missing"),
                              node,
                              i);
            g_free(node);

            // There are no other useful statistics from this.
            continue;
        }

        pretty_print_fuzzer(hdf, &system_call_fuzzers[i]);

        // Is the system call disabled?
        if (system_call_fuzzers[i].flags & SYS_DISABLED) {
            gchar *node = g_strdup_printf("%u.name", i);
            hdf_set_value(hdf_get_obj(hdf, "Global.fuzzer_disabled"),
                          node,
                          system_call_fuzzers[i].name);
            g_free(node);

            // Nothing else useful can happen to disabled fuzzers.
            continue;
        }

        // We can't do any more analysis if it has never been executed, so check here.
        if (system_call_fuzzers[i].total == 0)
            continue;

        // Does it always fail, but not marked SYS_FAIL?
        if (system_call_fuzzers[i].total == system_call_fuzzers[i].failures && !(system_call_fuzzers[i].flags & SYS_FAIL)) {
            gchar *node = g_strdup_printf("%u.name", i);
            hdf_set_value(hdf_get_obj(hdf, "Global.fuzzer_always_fails"),
                          node,
                          system_call_fuzzers[i].name);
            g_free(node);
        }

        // Does it always return the same value, but not marked SYS_BORING?
        if (((system_call_fuzzers[i].total == system_call_fuzzers[i].failures
                        && system_call_fuzzers[i].numerrors == 1)
                    || system_call_fuzzers[i].numerrors == 0)
                && !(system_call_fuzzers[i].flags & SYS_BORING)) {
            gchar *node = g_strdup_printf("%u.name", i);
            hdf_set_value(hdf_get_obj(hdf, "Global.fuzzer_always_same"),
                          node,
                          system_call_fuzzers[i].name);
            g_free(node);
        }

        // Is it marked SYS_BORING, but returns multiple value?
        if ((system_call_fuzzers[i].flags & SYS_BORING) && !(system_call_fuzzers[i].numerrors <= 1)) {
            gchar *node = g_strdup_printf("%u.name", i);
            hdf_set_value(hdf_get_obj(hdf, "Global.fuzzer_not_boring"),
                          node,
                          system_call_fuzzers[i].name);
            g_free(node);
        }

        // Is it marked SYS_FAIL, but succeeded?
        if ((system_call_fuzzers[i].flags & SYS_FAIL) && (system_call_fuzzers[i].failures != system_call_fuzzers[i].total)) {
            gchar *node = g_strdup_printf("%u.name", i);
            hdf_set_value(hdf_get_obj(hdf, "Global.fuzzer_not_failing"),
                          node,
                          system_call_fuzzers[i].name);
            g_free(node);
        }
    }

    return;
}
#endif
