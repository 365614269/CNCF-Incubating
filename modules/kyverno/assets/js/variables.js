// global variables;
const doc = document.documentElement;
const toggleId = "toggle";
const showId = "show";
const rootURL = window.location.protocol + "//" + window.location.host;

// config defined values
const pageLink = "{{ .RelPermalink }}";
const sparams = '{{ delimit site.Params.policies "," }}';
let allFiltersObj = [];
const policyTypeObj = { "type": "policytype", "policies": sparams.split(",") };
allFiltersObj.push(policyTypeObj);
const codeBlockConfig = JSON.parse('{{ partial "functions/getCodeConfig" . }}');

// simple strings
const storedValues = "kyvernoFilters";
const active = "active";
const policyTypeQueryString = "policytypes";
const hidden = "hidden";

