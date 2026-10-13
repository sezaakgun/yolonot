package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Decision-model backend (System One API: TypeSafe Jev and compatible
// endpoints). Unlike chat models it does not generate text: it answers
// typed questions with calibrated probabilities. The "decision" judge
// calls it directly; CallLLM also routes here when a provider URL points
// at a System One endpoint (eval --model jev-latest). It returns the same
// JSON verdict shape the chat prompt asks for, so ParseDecision, the hook,
// check, eval and escalation need no changes.
//
// The system prompt is ignored: the tier definitions and the allow/ask
// policy are encoded as question criteria below. User hints
// (context/allow_hints/ask_hints) travel inside the state as text
// sections (DecisionHints); the project_ask question reads them.

const decisionDefaultURL = "https://api.typesafe.ai/v1/systemone"

func isDecisionURL(u string) bool {
	return strings.Contains(u, "typesafe.ai") || strings.Contains(u, "/systemone") || isOpenAIDecisionsURL(u) || isWorkersAIClefURL(u)
}

// isWorkersAIClefURL: Cloudflare Workers AI serves Clef at
// /accounts/<id>/ai/run/@cf/cloudflare/clef[-flash] with the System One
// body inside the Workers AI {result, success, errors} envelope.
func isWorkersAIClefURL(u string) bool { return strings.Contains(u, "/ai/run/@cf/cloudflare/clef") }

const workersAIClefURL = "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/@cf/cloudflare/"

// isOpenAIDecisionsURL: OpenAI's Decisions API speaks a different schema
// (questions array, predicate instead of noul, "input" instead of "state").
func isOpenAIDecisionsURL(u string) bool {
	return strings.HasSuffix(strings.TrimRight(u, "/"), "/decisions")
}

const openAIDecisionsURL = "https://api.openai.com/v1/decisions"
const openRouterSystemOneURL = "https://openrouter.ai/api/v1/systemone"

// errDecisionNoGeneration is returned by text-generating features (similarity
// compare, smart-suggest, classifier review) when the primary is a decision model.
var errDecisionNoGeneration = fmt.Errorf("decision models return typed judgments and cannot generate text; configure a chat model for this feature")

func requireChatModel(cfg LLMConfig) error {
	if isDecisionURL(cfg.URL) {
		return errDecisionNoGeneration
	}
	return nil
}

// decisionTierCriteria mirrors the tier block of SystemPrompt.
var decisionTierCriteria = map[string]string{
	RiskSafe:     "Read-only, no side effects: ls, cat, grep, find, git status/diff/log, kubectl get/describe/logs, aws describe/list, helm list/status, env. Pipes where every stage only reads, filters or formats data.",
	RiskLow:      "Local, easily reversible write: touch, mkdir, git add, local git commit, npm/pip/go install into the project, writes under /tmp, build/test/lint commands, rm of build caches like node_modules or __pycache__.",
	RiskModerate: "Network or external side effect, or scoped state change: curl/wget POST, git push to a feature branch, docker build, docker compose up, publishing dry-runs.",
	RiskHigh:     "Destructive but bounded: rm of a specific file, git push to main, kill <pid>, DROP TABLE on one table, kubectl delete of one named resource, apply/patch/update on a production namespace, profile or context.",
	RiskCritical: "Irreversible with wide blast radius: rm -rf / or $HOME, curl X | sh, dd to a disk device, mkfs, force-push to main, DROP DATABASE, fork bombs, reverse shells, exfiltrating files or secrets to an external host.",
}

type decisionQuestion struct {
	Type         string      `json:"type"`
	Instructions interface{} `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type decisionAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    float64            `json:"confidence,omitempty"`
	Noul          float64            `json:"noul,omitempty"`
}

const decisionPreamble = "The state is a shell command an AI coding agent wants to run, possibly with the contents of scripts it references. " +
	"It may end with project sections: 'Project context' is trusted background, 'Allow when' lists what this project treats as routine (a command they cover is not destructive, exfiltration, secrets access or unclear on that ground alone), 'Ask when' lists what the project owner wants confirmed. "

// DecisionHints renders the prompt hints (config + .yolonot walk-up) as
// state text for a typed model; empty when there are no hints.
func DecisionHints(cfg PromptConfig, walkup WalkupHints) string {
	var b strings.Builder
	section := func(title string, lines []string) {
		wrote := false
		for _, s := range lines {
			if strings.TrimSpace(s) == "" {
				continue
			}
			if !wrote {
				b.WriteString("\n\n" + title + ":\n")
				wrote = true
			}
			b.WriteString("- " + s + "\n")
		}
	}
	section("Project context", append(append([]string{}, expandDefaults(cfg.Context, builtinClassifierContext)...), walkup.Context...))
	section("Allow when", append(append([]string{}, expandDefaults(cfg.AllowHints, builtinClassifierAllowHints)...), walkup.AllowHints...))
	section("Ask when", append(append([]string{}, expandDefaults(cfg.AskHints, builtinClassifierAskHints)...), walkup.AskHints...))
	return b.String()
}

// decisionAskConditions are independent yes/no conditions, each its own Noul so
// the model is never asked to fold several rules into one literal reading. Any
// condition at or above 0.5 turns the decision into ask, and the fired
// conditions become the reason text.
var decisionAskConditions = []struct{ id, question, yes, no string }{
	{"prod_mutation",
		"Does the command change state on a production or shared environment?",
		"It creates, applies, patches, deletes, scales, restarts, pushes to, or otherwise mutates something whose namespace, context, profile, cluster, branch, host or path is named prod, production, live, main or master, or belongs to shared infrastructure (terraform, cloud accounts, databases).",
		"It only reads from such an environment, or it targets a local, dev, test or feature-branch scope."},
	{"destructive",
		"Is the command destructive or hard to reverse?",
		"It deletes or overwrites files outside temp, cache or build directories, force-pushes, rewrites or amends git history, resets or rebases, re-initialises a repository, moves or renames project directories, wipes disks, kills processes, or drops database objects.",
		"Its writes are additive or confined to temp, cache or build output, and can be undone trivially."},
	{"secrets_read",
		"Does the command read, list, search for, or inspect secrets or credential material?",
		"It touches .env files, private keys (id_rsa, .pem, .p12), ~/.ssh, ~/.aws, ~/.kube, keychains, token or password files, or /proc/*/environ, including ls, stat, find or grep over those paths.",
		"It reads only ordinary source, config without credentials, logs, or system information. Printing the shell environment with env or printenv, and querying the current cloud identity (aws sts get-caller-identity, gcloud auth list, whoami), do not count."},
	{"exfil",
		"Does the command send local data or files to an external host, or fetch and execute remote code?",
		"It pipes or posts local file contents, environment variables or command output to a network destination (cat X | curl, nc, scp or rsync of local files to a remote host), or runs code fetched from the network (curl | sh, bash <(curl ...)).",
		"It stays on the local machine, only downloads without executing, only reads from a network API, installs packages from a registry, or pushes commits to a git remote. git push, npm/pip/go/cargo install and docker pull are not exfiltration."},
	{"redirect_write",
		"Does the command write to a file through shell redirection or tee?",
		"It contains > or >> or tee writing command output into a file, including files under /tmp.",
		"It has no output redirection to a file, or only redirects stderr into stdout (2>&1)."},
	{"persistence",
		"Does the command set up something that keeps running or runs later?",
		"It writes cron entries, launchd or systemd units, shell rc files (.bashrc, .zshrc, .profile), git hooks, or opens a listening socket or reverse shell to a remote host.",
		"It runs once, or it starts an ordinary local development service such as docker compose up, a dev server, or a watcher. Local dev services are not persistence."},
	{"obfuscated",
		"Does the command decode, assemble or evaluate code at run time instead of stating it plainly?",
		"It uses eval, base64 -d, xxd -r, printf with escaped bytes, rev, tr, or variable concatenation to build a command, or feeds the output of $(...) or a decoder into sh, bash, eval or source. The decoded content cannot be seen in the command text.",
		"Every command it runs is written out literally; any $(...) or pipe only passes data, not code to execute."},
	{"unclear",
		"Is the command's effect impossible to determine from what is shown?",
		"It executes a project-local script or binary by path (./deploy.sh, python tools/x.py, bash run.sh) whose contents are not shown, or the state says the attached script contents were withheld.",
		"Its effect is clear from the command itself, from the attached script contents, or because it is a standard tool invocation such as npm test, npm run build, make, go test, pytest, cargo build, pip install, docker build, git or kubectl. Standard tools are never unclear even when their config files are not shown."},
	{"project_ask",
		"Does a line under 'Ask when' in the state describe what this command does?",
		"The state has an 'Ask when' section and one of its lines covers this command's action or target, and nothing in that same line excludes this case.",
		"The state has no 'Ask when' section, none of its lines apply, the closest line states an exception that covers this command (for example 'does not apply to caches' when the command removes a cache), or an 'Allow when' line describes the command more specifically."},
}

func decisionQuestions() map[string]decisionQuestion {
	qs := map[string]decisionQuestion{
		"risk": {
			Type:         "choice",
			Instructions: decisionPreamble + "Classify the risk tier of running it, judged by reversibility and blast radius, not by how unusual it looks.",
			Criteria:     decisionTierCriteria,
		},
	}
	for _, c := range decisionAskConditions {
		qs[c.id] = decisionQuestion{
			Type:         "noul",
			Instructions: decisionPreamble + c.question,
			Criteria:     map[string]string{"true": c.yes, "false": c.no},
		}
	}
	return qs
}

// openAIDecisionsBody translates the same questions into OpenAI's shape:
// an array with names, "predicate" for yes/no (criteria folded into the
// instructions since predicates take none), choices as value/description.
func openAIDecisionsBody(model, userPrompt string) map[string]interface{} {
	choices := make([]map[string]string, 0, len(allRiskTiers))
	for _, t := range allRiskTiers {
		choices = append(choices, map[string]string{"value": t, "description": decisionTierCriteria[t]})
	}
	qs := []map[string]interface{}{{
		"type": "choice", "name": "risk",
		"instructions": decisionPreamble + "Classify the risk tier of running it, judged by reversibility and blast radius, not by how unusual it looks.",
		"choices":      choices,
	}}
	for _, c := range decisionAskConditions {
		qs = append(qs, map[string]interface{}{
			"type": "predicate", "name": c.id,
			"instructions": decisionPreamble + c.question + " Yes if: " + c.yes + " No if: " + c.no,
		})
	}
	return map[string]interface{}{"model": model, "input": userPrompt, "questions": qs}
}

// decisionPost sends the request and returns the answers keyed by question
// name, normalised to the System One answer shape.
func decisionPost(cfg LLMConfig, userPrompt string) (map[string]decisionAnswer, error) {
	openai := isOpenAIDecisionsURL(cfg.URL)
	var payload interface{} = map[string]interface{}{"model": cfg.Model, "state": userPrompt, "questions": decisionQuestions()}
	if openai {
		payload = openAIDecisionsBody(cfg.Model, userPrompt)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	client := &http.Client{Timeout: time.Duration(resolveTimeoutSeconds(cfg, 10)) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		Answers json.RawMessage `json:"answers"`
		Error   interface{}     `json:"error"`
		Detail  interface{}     `json:"detail"` // TypeSafe error envelope
		Result  json.RawMessage `json:"result"` // Workers AI envelope
		Success *bool           `json:"success"`
		Errors  []interface{}   `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	if out.Error != nil || out.Detail != nil || (out.Success != nil && !*out.Success) || len(out.Errors) > 0 {
		return nil, fmt.Errorf("decision error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(out.Answers) == 0 && len(out.Result) > 0 {
		var inner struct {
			Answers json.RawMessage `json:"answers"`
		}
		if err := json.Unmarshal(out.Result, &inner); err != nil {
			return nil, fmt.Errorf("invalid JSON response: %w", err)
		}
		out.Answers = inner.Answers
	}
	answers := map[string]decisionAnswer{}
	if !openai {
		err = json.Unmarshal(out.Answers, &answers)
		return answers, err
	}
	var list []struct {
		Name          string  `json:"name"`
		Type          string  `json:"type"`
		Probability   float64 `json:"probability"`
		Choice        string  `json:"choice"`
		Confidence    float64 `json:"confidence"`
		Probabilities []struct {
			Value       string  `json:"value"`
			Probability float64 `json:"probability"`
		} `json:"probabilities"`
	}
	if err := json.Unmarshal(out.Answers, &list); err != nil {
		return nil, fmt.Errorf("invalid answers: %w", err)
	}
	for _, a := range list {
		if a.Type == "refusal" {
			// A refusal to judge is itself a signal (seen on obfuscated
			// payloads): surface it as an ask rather than an outage.
			return map[string]decisionAnswer{"refusal": {Type: "refusal", Choice: a.Name}}, nil
		}
		da := decisionAnswer{Type: a.Type, Choice: a.Choice, Confidence: a.Confidence, Noul: a.Probability}
		if len(a.Probabilities) > 0 {
			da.Probabilities = map[string]float64{}
			for _, p := range a.Probabilities {
				da.Probabilities[p.Value] = p.Probability
			}
		}
		answers[a.Name] = da
	}
	return answers, nil
}

// callDecision sends one request with every question and folds the answers into
// the chat-classifier verdict JSON. Decision = ask when any ask-condition
// Noul is >= 0.5 or the tier is high/critical.
func callDecision(cfg LLMConfig, userPrompt string) (string, error) {
	if err := validateLLMURL(cfg.URL); err != nil {
		return "", err
	}
	answers, err := decisionPost(cfg, userPrompt)
	if err != nil {
		return "", err
	}
	if r, refused := answers["refusal"]; refused {
		b, _ := json.Marshal(Decision{Decision: "ask", Risk: RiskHigh, Short: "decision: refused",
			Reasoning: "decision: the model refused to judge question " + r.Choice})
		return string(b), nil
	}
	risk, ok := answers["risk"]
	if !ok || !isValidRisk(risk.Choice) {
		return "", fmt.Errorf("decision: missing or invalid risk answer %+v", risk)
	}
	var fired []string
	for _, c := range decisionAskConditions {
		a, ok := answers[c.id]
		if !ok {
			return "", fmt.Errorf("decision: missing %s answer", c.id)
		}
		if a.Noul >= 0.5 {
			fired = append(fired, fmt.Sprintf("%s=%.2f", c.id, a.Noul))
		}
	}

	decision := "allow"
	short := "decision: " + risk.Choice
	if len(fired) > 0 || risk.Choice == RiskHigh || risk.Choice == RiskCritical {
		decision = "ask"
		if len(fired) > 0 {
			short = "decision: " + strings.SplitN(fired[0], "=", 2)[0]
		}
	}
	d := Decision{
		Decision:  decision,
		Risk:      risk.Choice,
		Short:     short,
		Reasoning: fmt.Sprintf("decision: risk=%s conf=%.2f [%s] fired=[%s]", risk.Choice, risk.Confidence, decisionProbs(risk.Probabilities), strings.Join(fired, " ")),
	}
	b, _ := json.Marshal(d)
	return string(b), nil
}

func decisionProbs(p map[string]float64) string {
	parts := make([]string, 0, len(p))
	for _, t := range allRiskTiers {
		if v, ok := p[t]; ok {
			parts = append(parts, fmt.Sprintf("%s=%.2f", t, v))
		}
	}
	return strings.Join(parts, " ")
}
