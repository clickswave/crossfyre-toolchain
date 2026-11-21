//! The CVE leads a scan was given, toolmark's for its target, and what the scan's
//! templates said of each. Only a template's finding confirms a lead. A template that ran
//! and found nothing says the lead was checked and not found, which is not proof the host
//! is safe, and one that did not run says why.

use crate::template::Template;
use cfx_cve::inventory::{Answer, HostLead, LeadAnswer, NOT_PROOF};
use serde_json::{Value, json};

/// What became of one template in the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It found what it checks.
    Found,
    /// It ran and found nothing.
    Ran,
    /// It did not run, for this reason.
    NotRun(String),
}

/// The leads of a scan, and the templates of the scan that check each one.
pub struct Leads<'a> {
    leads: &'a [HostLead],
    from: &'a str,
    /// For each lead, the templates for its CVE and what became of each.
    seen: Vec<Vec<(String, Outcome)>>,
}

impl<'a> Leads<'a> {
    pub fn new(leads: &'a [HostLead], from: &'a str) -> Self {
        Self {
            leads,
            from,
            seen: vec![Vec::new(); leads.len()],
        }
    }

    /// `tmpl` came to `outcome`, for each lead whose CVE it checks.
    pub fn record(&mut self, tmpl: &Template, outcome: Outcome) {
        for (lead, seen) in self.leads.iter().zip(self.seen.iter_mut()) {
            if tmpl.checks_cve(&lead.cve) {
                seen.retain(|(id, _)| *id != tmpl.id);
                seen.push((tmpl.id.clone(), outcome.clone()));
            }
        }
    }

    /// The template `id`, already recorded, came to `outcome` after all, as one waiting on
    /// an out-of-band callback does.
    pub fn update(&mut self, id: &str, outcome: Outcome) {
        for seen in &mut self.seen {
            for (template, was) in seen.iter_mut() {
                if template == id {
                    *was = outcome.clone();
                }
            }
        }
    }

    /// The `leads` event a scan starts with, or None when it was given none.
    pub fn given(&self) -> Option<Value> {
        (!self.leads.is_empty())
            .then(|| json!({"type": "leads", "leads": self.leads, "from": self.from}))
    }

    /// The answer to each lead, as the `lead_answers` event, or None when there were no
    /// leads. `unrun` is why no template ran at all, when none did.
    pub fn answers(&self, unrun: Option<&str>) -> Option<Value> {
        if self.leads.is_empty() {
            return None;
        }
        let answers: Vec<(Answer, Option<&str>, Option<&str>)> = self
            .seen
            .iter()
            .map(|seen| {
                let first = |want: &dyn Fn(&Outcome) -> bool| {
                    seen.iter()
                        .find(|(_, o)| want(o))
                        .map(|(id, o)| (id.as_str(), o))
                };
                if let Some((id, _)) = first(&|o| *o == Outcome::Found) {
                    (Answer::Confirmed, Some(id), None)
                } else if let Some((id, _)) = first(&|o| *o == Outcome::Ran) {
                    (Answer::NotFound, Some(id), None)
                } else if let Some((id, Outcome::NotRun(why))) =
                    first(&|o| matches!(o, Outcome::NotRun(_)))
                {
                    (Answer::NotChecked, Some(id), Some(why.as_str()))
                } else {
                    (
                        Answer::NotChecked,
                        None,
                        Some(unrun.unwrap_or("no template checks it")),
                    )
                }
            })
            .collect();
        let rows: Vec<LeadAnswer> = self
            .leads
            .iter()
            .zip(&answers)
            .map(|(lead, (answer, template, reason))| LeadAnswer {
                cve: lead.cve.clone(),
                product: lead.product.clone(),
                answer: *answer,
                template: template.map(str::to_string),
                reason: reason.map(str::to_string),
            })
            .collect();
        let mut event = json!({
            "type": "lead_answers",
            "from": self.from,
            "answers": rows,
            "message": self.message(&answers),
        });
        if answers.iter().any(|(a, ..)| *a == Answer::NotFound) {
            event["not_proof"] = json!(NOT_PROOF);
        }
        Some(event)
    }

    /// The answers in a line or two: the CVEs confirmed and those checked and not found by
    /// name, and those not checked counted by why, as a lead list can run to dozens.
    fn message(&self, answers: &[(Answer, Option<&str>, Option<&str>)]) -> String {
        let cves = |want: Answer| -> Vec<&str> {
            let mut list: Vec<&str> = Vec::new();
            for (lead, (a, ..)) in self.leads.iter().zip(answers) {
                if *a == want && !list.contains(&lead.cve.as_str()) {
                    list.push(&lead.cve);
                }
            }
            list
        };
        let mut parts = Vec::new();
        for want in [Answer::Confirmed, Answer::NotFound] {
            let list = cves(want);
            if !list.is_empty() {
                parts.push(format!(
                    "{} {} ({})",
                    list.len(),
                    want.as_str(),
                    list.join(", ")
                ));
            }
        }
        let mut why: Vec<(&str, usize)> = Vec::new();
        for (a, _, reason) in answers {
            if *a == Answer::NotChecked {
                let reason = reason.unwrap_or_default();
                match why.iter_mut().find(|(r, _)| *r == reason) {
                    Some((_, n)) => *n += 1,
                    None => why.push((reason, 1)),
                }
            }
        }
        if !why.is_empty() {
            let total: usize = why.iter().map(|(_, n)| n).sum();
            let said: Vec<String> = why.iter().map(|(r, n)| format!("{n} {r}")).collect();
            parts.push(format!("{total} not checked: {}", said.join(", ")));
        }
        let mut message = format!(
            "{} CVE leads from {}: {}.",
            self.leads.len(),
            self.from,
            parts.join("; ")
        );
        if answers.iter().any(|(a, ..)| *a == Answer::NotFound) {
            message.push(' ');
            message.push_str(NOT_PROOF);
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(id: &str, cve: &str) -> Template {
        serde_yaml::from_str(&format!(
            "id: {id}\ninfo:\n  classification:\n    cve-id: {cve}\nhttp: []\n"
        ))
        .unwrap()
    }

    fn lead(cve: &str) -> HostLead {
        HostLead {
            cve: cve.into(),
            product: "Apache HTTP Server".into(),
            severity: "high".into(),
            kev: false,
        }
    }

    const FROM: &str = "toolmark's inventory of app.test:80, last seen 1 hour before the scan";

    /// A lead is confirmed only by its template's finding, checked and not found when the
    /// template ran and found nothing, with the line that this is not proof, and not
    /// checked, with why, when no template for it ran.
    #[test]
    fn each_lead_gets_its_templates_answer() {
        let given = [
            lead("CVE-2021-41773"),
            lead("CVE-2021-42013"),
            lead("CVE-2099-0001"),
            lead("CVE-2099-0002"),
        ];
        let mut leads = Leads::new(&given, FROM);
        leads.record(
            &template("CVE-2021-41773", "CVE-2021-41773"),
            Outcome::Found,
        );
        leads.record(&template("CVE-2021-42013", "cve-2021-42013"), Outcome::Ran);
        leads.record(
            &template("CVE-2099-0002", "CVE-2099-0002"),
            Outcome::NotRun("below the severities asked for".into()),
        );
        leads.record(&template("unrelated", "CVE-2000-0000"), Outcome::Found);
        let event = leads.answers(None).unwrap();
        assert_eq!(
            event["answers"],
            json!([
                {"cve": "CVE-2021-41773", "product": "Apache HTTP Server",
                 "answer": "confirmed", "template": "CVE-2021-41773"},
                {"cve": "CVE-2021-42013", "product": "Apache HTTP Server",
                 "answer": "checked, not found", "template": "CVE-2021-42013"},
                {"cve": "CVE-2099-0001", "product": "Apache HTTP Server",
                 "answer": "not checked", "reason": "no template checks it"},
                {"cve": "CVE-2099-0002", "product": "Apache HTTP Server",
                 "answer": "not checked", "template": "CVE-2099-0002",
                 "reason": "below the severities asked for"},
            ])
        );
        assert_eq!(event["not_proof"], NOT_PROOF);
        assert_eq!(
            event["message"],
            format!(
                "4 CVE leads from {FROM}: 1 confirmed (CVE-2021-41773); 1 checked, not found \
                 (CVE-2021-42013); 2 not checked: 1 no template checks it, 1 below the \
                 severities asked for. {NOT_PROOF}"
            )
        );
        assert!(!event.to_string().contains("exploitable"));
    }

    /// A template waiting on an out-of-band callback that came is confirmed after all, and
    /// with none checked, no line about proof is said.
    #[test]
    fn a_callback_that_came_confirms_the_lead() {
        let given = [lead("CVE-2021-44228")];
        let mut leads = Leads::new(&given, FROM);
        leads.record(&template("CVE-2021-44228", "CVE-2021-44228"), Outcome::Ran);
        leads.update("CVE-2021-44228", Outcome::Found);
        let event = leads.answers(None).unwrap();
        assert_eq!(event["answers"][0]["answer"], "confirmed");
        assert!(event.get("not_proof").is_none(), "{event}");
    }

    /// When no template ran at all, every lead says why, and a scan given no leads says
    /// nothing of them.
    #[test]
    fn with_no_template_run_each_lead_says_why() {
        let given = [lead("CVE-2021-41773")];
        let leads = Leads::new(&given, FROM);
        let event = leads.answers(Some("the target did not answer")).unwrap();
        assert_eq!(event["answers"][0]["answer"], "not checked");
        assert_eq!(event["answers"][0]["reason"], "the target did not answer");
        assert!(Leads::new(&[], FROM).answers(None).is_none());
        assert!(Leads::new(&[], FROM).given().is_none());
    }

    /// A template may name its CVE as nuclei does, one or a list.
    #[test]
    fn a_template_names_its_cve_as_one_or_a_list() {
        let list: Template = serde_yaml::from_str(
            "id: two\ninfo:\n  classification:\n    cve-id:\n      - CVE-2021-41773\n      - CVE-2021-42013\n",
        )
        .unwrap();
        assert!(list.checks_cve("CVE-2021-42013"));
        assert!(template("one", "CVE-2021-41773").checks_cve("cve-2021-41773"));
        assert!(!template("one", "CVE-2021-41773").checks_cve("CVE-2021-42013"));
    }
}
