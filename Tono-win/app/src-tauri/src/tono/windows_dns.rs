//! Bounded access to the Windows DNS Client resolver.
//!
//! Tokio's `lookup_host` delegates to `getaddrinfo`, whose blocking work keeps
//! running after an async timeout. That is especially harmful immediately after
//! changing adapter DNS: one stale query can occupy a worker while subsequent
//! verification attempts pile up behind it. `DnsQueryEx` gives us the same
//! system resolver with cache bypass, an A-only query, and a real cancellation
//! handle.

use std::{
    ffi::c_void,
    net::Ipv4Addr,
    ptr,
    sync::{Condvar, Mutex},
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{DNS_REQUEST_PENDING, ERROR_SUCCESS},
    NetworkManagement::Dns::{
        DNS_QUERY_BYPASS_CACHE, DNS_QUERY_CANCEL, DNS_QUERY_NO_HOSTS_FILE, DNS_QUERY_REQUEST,
        DNS_QUERY_REQUEST_VERSION1, DNS_QUERY_RESULT, DNS_QUERY_RESULTS_VERSION1, DNS_QUERY_TREAT_AS_FQDN, DNS_RECORDA,
        DNS_TYPE_A, DnsCancelQuery, DnsFree, DnsFreeRecordList, DnsQueryEx,
    },
};

#[derive(Debug)]
enum QueryOutcome {
    Answer(Vec<Ipv4Addr>),
    Error(i32),
}

#[derive(Default)]
struct Completion {
    outcome: Mutex<Option<QueryOutcome>>,
    ready: Condvar,
}

/// Run one A-only query through the Windows DNS Client. The returned future is
/// bounded even though the native API is callback based; on timeout the worker
/// asks DNSAPI to cancel and waits for the mandatory completion callback only
/// on Tokio's blocking pool.
pub async fn query_a(host: &str, timeout: Duration) -> Result<Vec<Ipv4Addr>, String> {
    let host = host.to_owned();
    let worker = tokio::task::spawn_blocking(move || query_a_blocking(&host, timeout));

    // `DnsCancelQuery` is non-blocking. Leave a small cleanup margin for the
    // callback after the worker's own deadline, without ever stranding the
    // connection transaction if a third-party DNS provider wedges DNSAPI.
    match tokio::time::timeout(timeout + Duration::from_secs(2), worker).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(format!("Windows DNS worker failed: {error}")),
        Err(_) => Err(format!(
            "Windows system DNS A query exceeded {timeout:?} and cancellation did not settle"
        )),
    }
}

fn query_a_blocking(host: &str, timeout: Duration) -> Result<Vec<Ipv4Addr>, String> {
    if host.is_empty() || host.encode_utf16().any(|unit| unit == 0) {
        return Err("Windows system DNS query received an invalid host name".to_string());
    }

    let wide_name: Vec<u16> = host.encode_utf16().chain(std::iter::once(0)).collect();
    let completion = Completion::default();
    let mut result = DNS_QUERY_RESULT {
        Version: DNS_QUERY_RESULTS_VERSION1,
        ..Default::default()
    };
    let mut cancel = DNS_QUERY_CANCEL::default();
    let request = DNS_QUERY_REQUEST {
        Version: DNS_QUERY_REQUEST_VERSION1,
        QueryName: wide_name.as_ptr(),
        QueryType: DNS_TYPE_A,
        QueryOptions: u64::from(DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_TREAT_AS_FQDN),
        pDnsServerList: ptr::null_mut(),
        InterfaceIndex: 0,
        pQueryCompletionCallback: Some(query_complete),
        pQueryContext: ptr::from_ref(&completion).cast_mut().cast::<c_void>(),
    };

    // SAFETY: `request`, `wide_name`, `result`, `cancel`, and `completion` all
    // remain alive until a synchronous result is consumed or the asynchronous
    // completion callback has run. The callback only reads DNSAPI-owned records
    // during its invocation and frees them exactly once afterwards.
    let status = unsafe { DnsQueryEx(&request, &mut result, &mut cancel) };
    if status != DNS_REQUEST_PENDING {
        return finish_sync_query(status, &mut result);
    }

    let mut outcome = completion
        .outcome
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (guard, wait_result) = completion
        .ready
        .wait_timeout_while(outcome, timeout, |value| value.is_none())
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    outcome = guard;
    if wait_result.timed_out() && outcome.is_none() {
        drop(outcome);
        // SAFETY: DNSAPI populated `cancel` for this still-pending query and it
        // stays alive until the completion callback below releases the wait.
        let _ = unsafe { DnsCancelQuery(&cancel) };
        outcome = completion
            .outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while outcome.is_none() {
            outcome = completion
                .ready
                .wait(outcome)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        return Err(format!("Windows system DNS A query exceeded {timeout:?}"));
    }

    match outcome.take() {
        Some(outcome) => format_outcome(outcome),
        None => Err("Windows DNS completion callback returned without a result".to_string()),
    }
}

fn finish_sync_query(status: i32, result: &mut DNS_QUERY_RESULT) -> Result<Vec<Ipv4Addr>, String> {
    let outcome = if status == ERROR_SUCCESS as i32 {
        // A synchronous DnsQueryEx reports its final status in the result too.
        query_outcome(result)
    } else {
        free_records(result);
        QueryOutcome::Error(status)
    };
    format_outcome(outcome)
}

unsafe extern "system" fn query_complete(context: *const c_void, result: *mut DNS_QUERY_RESULT) {
    if context.is_null() || result.is_null() {
        return;
    }

    // SAFETY: the caller keeps `Completion` and `DNS_QUERY_RESULT` alive until
    // this callback fires, as required by DnsQueryEx. The callback is the sole
    // consumer of records on the asynchronous path.
    let completion = unsafe { &*context.cast::<Completion>() };
    let outcome = unsafe { query_outcome(&mut *result) };
    let mut slot = completion
        .outcome
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(outcome);
    drop(slot);
    completion.ready.notify_all();
}

fn query_outcome(result: &mut DNS_QUERY_RESULT) -> QueryOutcome {
    if result.QueryStatus != ERROR_SUCCESS as i32 {
        let status = result.QueryStatus;
        free_records(result);
        return QueryOutcome::Error(status);
    }

    let addresses = collect_a_records(result.pQueryRecords);
    free_records(result);
    QueryOutcome::Answer(addresses)
}

fn collect_a_records(mut record: *mut DNS_RECORDA) -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    // DNSAPI owns this acyclic list. Keep a defensive cap so corrupt third-party
    // resolver output can never turn verification into an unbounded walk.
    for _ in 0..128 {
        if record.is_null() {
            break;
        }
        // SAFETY: `record` comes from the live DNSAPI result list and is only
        // read before the list is freed. The union's A arm is valid for A RRs.
        let item = unsafe { &*record };
        if item.wType == DNS_TYPE_A && usize::from(item.wDataLength) >= size_of::<u32>() {
            let raw = unsafe { item.Data.A.IpAddress };
            addresses.push(ipv4_from_dns_word(raw));
        }
        record = item.pNext;
    }
    addresses
}

fn free_records(result: &mut DNS_QUERY_RESULT) {
    if !result.pQueryRecords.is_null() {
        // SAFETY: the pointer was allocated by DNSAPI for this result and this
        // function clears it immediately, preventing a second free.
        unsafe { DnsFree(result.pQueryRecords.cast(), DnsFreeRecordList) };
        result.pQueryRecords = ptr::null_mut();
    }
}

fn ipv4_from_dns_word(raw: u32) -> Ipv4Addr {
    // DNS_A_DATA stores the four network-order octets in memory. `to_ne_bytes`
    // preserves that memory order on both little- and big-endian targets.
    Ipv4Addr::from(raw.to_ne_bytes())
}

fn format_outcome(outcome: QueryOutcome) -> Result<Vec<Ipv4Addr>, String> {
    match outcome {
        QueryOutcome::Answer(addresses) if addresses.is_empty() => {
            Err("Windows system DNS A query returned no A records".to_string())
        }
        QueryOutcome::Answer(addresses) => Ok(addresses),
        QueryOutcome::Error(status) => Err(format!(
            "Windows system DNS A query failed with status {status}: {}",
            std::io::Error::from_raw_os_error(status)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{QueryOutcome, format_outcome, ipv4_from_dns_word};
    use std::net::Ipv4Addr;

    #[test]
    fn dns_a_word_keeps_wire_octet_order() {
        let raw = u32::from_ne_bytes([198, 18, 7, 9]);
        assert_eq!(ipv4_from_dns_word(raw), Ipv4Addr::new(198, 18, 7, 9));
    }

    #[test]
    fn an_empty_success_is_not_a_dns_proof() {
        assert!(format_outcome(QueryOutcome::Answer(Vec::new())).is_err());
    }
}
