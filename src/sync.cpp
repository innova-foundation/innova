// Copyright (c) 2011-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sync.h"

#include "util.h"

#include <boost/foreach.hpp>
#ifdef DEBUG_LOCKORDER
#include <boost/thread.hpp>
#include <map>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif
#endif

#ifdef DEBUG_LOCKCONTENTION
void PrintLockContention(const char* pszName, const char* pszFile, int nLine)
{
    printf("LOCKCONTENTION: %s\n", pszName);
    printf("Locker: %s:%d\n", pszFile, nLine);
}
#endif /* DEBUG_LOCKCONTENTION */

#ifdef DEBUG_LOCKORDER
//
// Early deadlock detection.
// Problem being solved:
//    Thread 1 locks  A, then B, then C
//    Thread 2 locks  D, then C, then A
//     --> may result in deadlock between the two threads, depending on when they run.
// Solution implemented here:
// Keep track of pairs of locks: (A before B), (A before C), etc.
// Complain if any thread tries to lock in a different order.
//

struct CLockLocation
{
    CLockLocation(const char* pszName, const char* pszFile, int nLine)
    {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
        nWaitStart = GetTimeMillis();
        fAcquired = false;
    }

    std::string ToString() const
    {
        return mutexName+"  "+sourceFile+":"+itostr(sourceLine);
    }

    std::string MutexName() const { return mutexName; }

    int64_t WaitStart() const { return nWaitStart; }
    bool Acquired() const { return fAcquired; }
    void MarkAcquired() { fAcquired = true; }

private:
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
    int64_t nWaitStart;
    bool fAcquired;
};

typedef std::vector< std::pair<void*, CLockLocation> > LockStack;

static boost::mutex dd_mutex;
static std::map<std::pair<void*, void*>, LockStack> lockorders;
static boost::thread_specific_ptr<LockStack> lockstack;

// Live stacks by OS thread id, so the wait-for graph can be read from outside
// the thread that owns it. Entries are dropped when a stack empties, which is
// how a thread deregisters on exit.
struct CThreadLocks
{
    std::string strName;
    LockStack* pstack;
};
static std::map<uint64_t, CThreadLocks> livestacks;

static uint64_t ThreadIdNum()
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)(uintptr_t)pthread_self();
#endif
}

static std::string ThreadNameStr()
{
#ifdef __linux__
    char name[17];
    memset(name, 0, sizeof(name));
    if (prctl(PR_GET_NAME, name, 0, 0, 0) == 0)
        return std::string(name);
#endif
    return std::string("?");
}

static int64_t nLockWatchdogSecs = -1;
static int64_t nLastWatchdogDump = 0;
static bool fLockTrace = false;

// Builds the whole report under dd_mutex and prints it after releasing: the
// logging path itself takes instrumented locks, so printing while holding
// dd_mutex would re-enter push_lock on a non-recursive mutex.
static void LockWatchdogLoop()
{
    RenameThread("innova-lockwd");
    for (;;)
    {
        MilliSleep(5000);
        std::string strReport;
        {
            boost::mutex::scoped_lock lock(dd_mutex);
            int64_t nNow = GetTimeMillis();
            int64_t nWorst = 0;
            std::string strWorst;
            for (std::map<uint64_t, CThreadLocks>::const_iterator it = livestacks.begin();
                 it != livestacks.end(); ++it)
            {
                const LockStack& s = *it->second.pstack;
                for (size_t i = 0; i < s.size(); i++)
                {
                    if (s[i].second.Acquired())
                        continue;
                    int64_t nWait = nNow - s[i].second.WaitStart();
                    if (nWait <= nWorst)
                        continue;
                    nWorst = nWait;
                    strWorst = strprintf("tid=%llu %s waited %.0fs for %s",
                                         (unsigned long long)it->first,
                                         it->second.strName.c_str(),
                                         nWait / 1000.0, s[i].second.ToString().c_str());
                }
            }
            if (nWorst < nLockWatchdogSecs * 1000)
                continue;
            if (nLastWatchdogDump != 0 && nNow - nLastWatchdogDump < 60000)
                continue;
            nLastWatchdogDump = nNow;

            strReport = strprintf("LOCKWATCHDOG: %s; %d thread(s) hold or wait on a lock\n",
                                  strWorst.c_str(), (int)livestacks.size());
            for (std::map<uint64_t, CThreadLocks>::const_iterator it = livestacks.begin();
                 it != livestacks.end(); ++it)
            {
                strReport += strprintf("  tid=%llu name=%s\n",
                                       (unsigned long long)it->first,
                                       it->second.strName.c_str());
                const LockStack& s = *it->second.pstack;
                for (size_t i = 0; i < s.size(); i++)
                {
                    if (s[i].second.Acquired())
                        strReport += "      HOLD " + s[i].second.ToString() + "\n";
                    else
                        strReport += strprintf("      WAIT %s   (%.1fs)\n",
                                               s[i].second.ToString().c_str(),
                                               (nNow - s[i].second.WaitStart()) / 1000.0);
                }
            }
        }
        printf("%s", strReport.c_str());
    }
}

static boost::once_flag watchdog_once = BOOST_ONCE_INIT;
static void StartLockWatchdog()
{
    fLockTrace = GetBoolArg("-debuglockorder", false);
    nLockWatchdogSecs = GetArg("-lockwatchdog", 90);
    if (nLockWatchdogSecs <= 0)
        return;
    new boost::thread(&LockWatchdogLoop);
}


static void potential_deadlock_detected(const std::pair<void*, void*>& mismatch, const LockStack& s1, const LockStack& s2)
{
    printf("POTENTIAL DEADLOCK DETECTED\n");
    printf("Previous lock order was:\n");
    BOOST_FOREACH(const PAIRTYPE(void*, CLockLocation)& i, s2)
    {
        if (i.first == mismatch.first) printf(" (1)");
        if (i.first == mismatch.second) printf(" (2)");
        printf(" %s\n", i.second.ToString().c_str());
    }
    printf("Current lock order is:\n");
    BOOST_FOREACH(const PAIRTYPE(void*, CLockLocation)& i, s1)
    {
        if (i.first == mismatch.first) printf(" (1)");
        if (i.first == mismatch.second) printf(" (2)");
        printf(" %s\n", i.second.ToString().c_str());
    }
}

static void push_lock(void* c, const CLockLocation& locklocation, bool fTry)
{
    boost::call_once(watchdog_once, &StartLockWatchdog);

    if (lockstack.get() == NULL)
        lockstack.reset(new LockStack);

    if (fLockTrace) printf("Locking: %s\n", locklocation.ToString().c_str());
    dd_mutex.lock();

    (*lockstack).push_back(std::make_pair(c, locklocation));
    if ((*lockstack).size() == 1)
    {
        CThreadLocks tl;
        tl.strName = ThreadNameStr();
        tl.pstack = lockstack.get();
        livestacks[ThreadIdNum()] = tl;
    }

    if (!fTry) {
        BOOST_FOREACH(const PAIRTYPE(void*, CLockLocation)& i, (*lockstack)) {
            if (i.first == c) break;

            std::pair<void*, void*> p1 = std::make_pair(i.first, c);
            if (lockorders.count(p1))
                continue;
            lockorders[p1] = (*lockstack);

            std::pair<void*, void*> p2 = std::make_pair(c, i.first);
            if (lockorders.count(p2))
            {
                potential_deadlock_detected(p1, lockorders[p2], lockorders[p1]);
                break;
            }
        }
    }
    dd_mutex.unlock();
}

static void pop_lock()
{
    if (fLockTrace)
    {
        const CLockLocation& locklocation = (*lockstack).rbegin()->second;
        printf("Unlocked: %s\n", locklocation.ToString().c_str());
    }
    dd_mutex.lock();
    (*lockstack).pop_back();
    if ((*lockstack).empty())
        livestacks.erase(ThreadIdNum());
    dd_mutex.unlock();
}

void EnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine), fTry);
}

void EnterCriticalAcquired()
{
    dd_mutex.lock();
    if (lockstack.get() != NULL && !(*lockstack).empty())
        (*lockstack).rbegin()->second.MarkAcquired();
    dd_mutex.unlock();
}

void LeaveCritical()
{
    pop_lock();
}

std::string LocksHeld()
{
    std::string result;
    BOOST_FOREACH(const PAIRTYPE(void*, CLockLocation)&i, *lockstack)
        result += i.second.ToString() + std::string("\n");
    return result;
}

void AssertLockHeldInternal(const char *pszName, const char* pszFile, int nLine, void *cs)
{
    BOOST_FOREACH(const PAIRTYPE(void*, CLockLocation)&i, *lockstack)
        if (i.first == cs) return;

    printf("Assertion failed: lock %s not held in %s:%i; locks held:\n%s\n",
            pszName, pszFile, nLine, LocksHeld().c_str());
    fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s",
            pszName, pszFile, nLine, LocksHeld().c_str());
    abort();
}

#endif /* DEBUG_LOCKORDER */
