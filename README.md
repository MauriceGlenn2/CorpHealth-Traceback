# CorpHealth — Operations Activity Review

## Background

Your organization recently completed a phased deployment of an internal 
platform known as **CorpHealth** — a lightweight system monitoring and 
maintenance framework designed to:

- Track endpoint stability and performance
- Run automated post-patch health checks
- Collect system diagnostics during maintenance windows
- Reduce manual workload for operations teams

CorpHealth operates using a mix of scheduled tasks, background services, 
and diagnostic scripts deployed across operational workstations.

To support this, IT provisioned a dedicated operational account. This 
account was granted local administrator privileges on specific systems 
in order to:

- Register scheduled maintenance tasks
- Install and remove system services
- Write diagnostic and configuration data to protected system locations
- Perform controlled cleanup and telemetry operations

It was designed to be used **only through approved automation frameworks**, 
not through interactive sign-ins.

---

## Anomalous Activity

In mid-November, routine monitoring began surfacing unusual activity tied 
to a workstation in the operations environment. At first glance, the 
activity appeared consistent with normal system maintenance tasks: health 
checks, scheduled runs, configuration updates, and inventory synchronization.

However, closer review raised concerns:

- Activity occurred outside normal maintenance windows
- Script execution patterns deviated from approved baselines
- Diagnostic processes were launched manually rather than through automation
- Some actions resembled behaviors often associated with credential 
  compromise or script misuse

Much of this activity was associated with an account that normally runs 
silently in the background.

---

## Your Role

You are taking over as the **lead analyst** assigned to review historical 
telemetry captured by:

- Microsoft Defender for Endpoint
- Azure diagnostic and device logs
- Supporting endpoint event artifacts

You will **not** have live access to the machine — only its recorded activity.

---

## Investigation Objectives

Your task is to determine:

- What system was affected
- When suspicious activity occurred
- How the activity progressed across different stages
- Whether the behavior represents authorized automation or misuse of a 
  privileged account

---

## Case Classification

The incident is not labeled as a confirmed breach. It has been formally 
categorized as:

> **"An Operations Activity Review"**

Your investigation will determine whether it remains just that — or 
escalates into something more.
