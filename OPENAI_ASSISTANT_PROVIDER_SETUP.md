# OpenAI Assistant Provider - Complete Setup Guide

## 🎯 What Was Created

A new **OpenAI Assistant Provider** for Keep that integrates with OpenAI's Assistants API, enabling:

✅ **Stateful conversations** (threads)
✅ **Knowledge base search** (File Search tool)
✅ **Code execution** (Code Interpreter)
✅ **Company-specific AI assistants**
✅ **Multi-turn troubleshooting**

---

## 📁 Files Created

### 1. Provider Implementation
- `keep/providers/openaiassistant_provider/__init__.py`
- `keep/providers/openaiassistant_provider/openaiassistant_provider.py`
- `keep/providers/openaiassistant_provider/openaiassistant_provider.yaml`
- `keep/providers/openaiassistant_provider/README.md`

### 2. Example Workflow
- `examples/workflows/ai_alert_triage_with_assistant.yaml`

### 3. Documentation
- This file: `OPENAI_ASSISTANT_PROVIDER_SETUP.md`

---

## 🚀 How to Use

### Step 1: Create Your OpenAI Assistant

1. Go to https://platform.openai.com/assistants
2. Click **"Create"**
3. Configure your assistant:

```
Name: Keep-Alert-Analyzer

Model: gpt-4o-mini (or gpt-4o for better quality)

Instructions:
You are an Alert Analysis Assistant for KeepHQ. You help on-call engineers 
diagnose alerts by providing root-cause insights and actionable recommendations.

Use the company knowledge base (uploaded files) to ground your answers. 
If information isn't in the knowledge base, say you don't have the info 
rather than guessing. Keep responses concise, factual, and helpful.

When analyzing alerts, always consider:
1. Severity and impact
2. Historical similar incidents
3. Company-specific mitigation steps
4. Whether escalation is needed

Respond in JSON format when requested with keys:
- action: "escalate" | "investigate" | "resolve"
- reason: detailed explanation
- severity: "critical" | "high" | "medium" | "low"
- related_docs: array of relevant documentation
```

4. **Enable Tools:**
   - ✅ File Search (for knowledge base)
   - ✅ Code Interpreter (for log analysis)

5. **Upload Files:**
   - Runbooks
   - Architecture diagrams
   - Past incident reports
   - Troubleshooting guides
   - API documentation

6. **Copy Assistant ID** (e.g., `asst_GPkwWwZeCdU68iUXSQ5wglGk`)

---

### Step 2: Configure in Keep

#### Option A: Via Keep UI

1. Navigate to **Providers** → **Add Provider**
2. Search for **"OpenAI Assistant"**
3. Fill in:
   - **Provider Name**: `my-assistant` (or any name)
   - **API Key**: Your OpenAI API key (`sk-...`)
   - **Organization ID**: (Optional) Your org ID
   - **Assistant ID**: The ID from Step 1
4. Click **"Test"** to verify connection
5. Click **"Save"**

#### Option B: Via Configuration File

Add to your Keep provider config:

```yaml
providers:
  my-assistant:
    type: openaiassistant
    authentication:
      api_key: sk-your-openai-key
      assistant_id: asst_GPkwWwZeCdU68iUXSQ5wglGk
      organization_id: org-your-org-id  # Optional
```

---

### Step 3: Create a Workflow

Copy the example workflow or create your own:

```yaml
workflow:
  id: ai-alert-triage
  description: AI-powered alert triage using OpenAI Assistant
  
  triggers:
    - type: alert
      filters:
        - key: severity
          value: "critical|high"
  
  actions:
    # Analyze the alert
    - name: analyze_alert
      provider:
        type: openaiassistant
        config: "{{ providers.my-assistant }}"
        with:
          prompt: |
            Analyze this alert:
            
            Name: {{ alert.name }}
            Message: {{ alert.message }}
            Severity: {{ alert.severity }}
            Source: {{ alert.source }}
            
            Provide:
            1. Root cause analysis
            2. Recommended action
            3. Severity assessment
            
            Respond in JSON format.
          max_wait_time: 60
          parse_json: true
    
    # Log the result
    - name: log_analysis
      provider:
        type: console
        with:
          message: |
            AI Decision: {{ steps.analyze_alert.results.response.action }}
            Reason: {{ steps.analyze_alert.results.response.reason }}
    
    # Escalate if needed
    - name: escalate_to_slack
      if: "{{ steps.analyze_alert.results.response.action == 'escalate' }}"
      provider:
        type: slack
        config: "{{ providers.slack }}"
        with:
          message: |
            🚨 ALERT REQUIRES ESCALATION
            
            {{ steps.analyze_alert.results.response.reason }}
```

---

## 🔥 Real-World Use Cases

### Use Case 1: Knowledge Base Search

**Your assistant can search uploaded documentation!**

```yaml
- name: search_runbooks
  provider:
    type: openaiassistant
    config: "{{ providers.my-assistant }}"
    with:
      prompt: |
        Alert: {{ alert.name }}
        
        Search our runbooks for:
        1. Similar past incidents
        2. Troubleshooting steps
        3. Known workarounds
```

### Use Case 2: Multi-Step Investigation

**Maintain context across multiple queries:**

```yaml
# Step 1: Initial analysis
- name: initial_analysis
  provider:
    type: openaiassistant
    config: "{{ providers.my-assistant }}"
    with:
      prompt: "What's causing this alert? {{ alert.message }}"

# Step 2: Follow-up in same thread
- name: get_remediation
  provider:
    type: openaiassistant
    config: "{{ providers.my-assistant }}"
    with:
      prompt: "What are the exact commands to fix this?"
      thread_id: "{{ steps.initial_analysis.results.thread_id }}"

# Step 3: Another follow-up
- name: check_impact
  provider:
    type: openaiassistant
    config: "{{ providers.my-assistant }}"
    with:
      prompt: "What services might be affected?"
      thread_id: "{{ steps.initial_analysis.results.thread_id }}"
```

### Use Case 3: Log Analysis with Code

**Assistant can run Python to parse logs:**

```yaml
- name: analyze_logs
  provider:
    type: openaiassistant
    config: "{{ providers.my-assistant }}"
    with:
      prompt: |
        These are error logs from our service:
        {{ alert.message }}
        
        Write and run Python code to:
        1. Parse the error patterns
        2. Count frequencies
        3. Identify the root cause
```

---

## 🆚 OpenAI vs OpenAI Assistant

| Feature | OpenAI Provider | OpenAI Assistant |
|---------|----------------|------------------|
| Speed | Fast (1-2s) | Slower (5-10s) |
| Stateful | ❌ No | ✅ Yes (threads) |
| Knowledge Base | ❌ No | ✅ Yes (File Search) |
| Code Execution | ❌ No | ✅ Yes (Interpreter) |
| JSON Output | ✅ Guaranteed | ⚠️ Best effort |
| Cost | $ | $$ |

**When to use OpenAI Provider:**
- Fast, simple triage
- High-volume alerts
- Guaranteed JSON output needed

**When to use OpenAI Assistant:**
- Complex investigations
- Need company documentation
- Multi-step troubleshooting
- Log/code analysis

---

## 💰 Pricing

**OpenAI Assistant costs:**
- **Model tokens**: Standard pricing (e.g., gpt-4o-mini: $0.15/$0.60 per 1M tokens)
- **File Search**: $0.10 per GB per day (for knowledge base files)
- **Code Interpreter**: $0.03 per session

**Example: 1000 alerts/day analyzed**
- Using gpt-4o-mini: ~$5-10/month
- Using gpt-4o: ~$50-100/month
- Plus file storage: ~$3/month for 1GB knowledge base

---

## 🧪 Testing

### Test Locally

```bash
# Set environment variables
export OPENAI_API_KEY=sk-your-key
export ASSISTANT_ID=asst-your-id

# Run the test script
cd keep/providers/openaiassistant_provider
python openaiassistant_provider.py
```

### Test in Keep

1. Create a test workflow with manual trigger
2. Run it with a sample alert
3. Check the logs for AI response
4. Verify thread continuity works

---

## 🐛 Troubleshooting

### Error: "Failed to retrieve assistant"
- ✅ Check your API key is correct
- ✅ Verify assistant ID format: `asst_...`
- ✅ Ensure assistant exists at https://platform.openai.com/assistants

### Error: "Assistant did not respond within X seconds"
- Increase `max_wait_time` parameter
- Check OpenAI status page
- Your assistant might be overloaded

### Response is not JSON
- Set `parse_json: false` to get raw text
- Add explicit JSON instructions to your prompt
- Use `additional_instructions` parameter

### Thread not maintaining context
- Verify you're passing `thread_id` from previous step
- Check: `{{ steps.previous_step.results.thread_id }}`

---

## 📊 Monitoring

**Track assistant performance:**

```yaml
- name: log_assistant_metrics
  provider:
    type: console
    with:
      message: |
        Thread: {{ steps.analyze.results.thread_id }}
        Run: {{ steps.analyze.results.run_id }}
        Messages: {{ steps.analyze.results.messages | length }}
```

**Check costs on OpenAI dashboard:**
- https://platform.openai.com/usage

---

## 🎓 Best Practices

### 1. Optimize System Instructions
- Be specific about output format
- Include company-specific context
- Define clear decision criteria

### 2. Use Threads Wisely
- Continue threads for related queries
- Don't reuse threads across different alerts
- Clean up old threads periodically

### 3. Upload Good Documentation
- Keep runbooks up-to-date
- Include past incident reports
- Add architecture diagrams

### 4. Handle Errors Gracefully
```yaml
- name: analyze_with_fallback
  provider:
    type: openaiassistant
    config: "{{ providers.my-assistant }}"
    with:
      prompt: "..."
    fail_on_error: false

- name: fallback_to_simple_ai
  if: "{{ steps.analyze_with_fallback.results is not defined }}"
  provider:
    type: openai  # Use simple OpenAI as fallback
    config: "{{ providers.openai }}"
    with:
      prompt: "..."
```

---

## 🔮 Future Enhancements

**Coming soon:**
- ✅ Function calling support (call external APIs from assistant)
- ✅ Streaming responses (real-time output)
- ✅ Vector store management (better knowledge base)
- ✅ Multi-assistant routing (different assistants for different alert types)

---

## 📚 Resources

- [OpenAI Assistants API Docs](https://platform.openai.com/docs/assistants/overview)
- [Keep Workflows Guide](https://docs.keephq.dev/workflows)
- [Example Workflow](examples/workflows/ai_alert_triage_with_assistant.yaml)
- [Provider README](keep/providers/openaiassistant_provider/README.md)

---

## 🎉 Summary

You now have a fully functional **OpenAI Assistant Provider** that can:

1. ✅ Connect to your custom OpenAI assistants
2. ✅ Search company knowledge bases
3. ✅ Execute code for analysis
4. ✅ Maintain conversation context
5. ✅ Provide AI-powered alert triage

**Next steps:**
1. Create your assistant on OpenAI platform
2. Configure the provider in Keep
3. Deploy your first AI triage workflow
4. Monitor and iterate!

🚀 **Happy AI-powered alerting!**

