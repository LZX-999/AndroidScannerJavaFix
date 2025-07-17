# Remove Anthropic, import google.generativeai
import google.generativeai as genai
import json
import logging
import re

logger = logging.getLogger(__name__)

from google.generativeai.types import FunctionDeclaration, Tool

# Define the schema for the report_vulnerability tool
report_vulnerability_func = FunctionDeclaration(
    name="report_vulnerability",
    description="Report a security vulnerability found in the code",
    parameters={
        "type": "object",
        "properties": {
            "vulnerability_type": {
                "type": "string",
                "description": "The type of vulnerability found"
            },
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                "description": "The severity of the vulnerability"
            },
            "affected_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List containing ONLY the relative path(s) to the affected file(s)"
            },
            "line_number": {
                "type": "integer",
                "description": "The primary starting line number within the file where the vulnerability occurs."
            },
            "description": {
                "type": "string",
                "description": "Detailed description of the vulnerability"
            },
            "code_snippet": {
                "type": "string",
                "description": "Relevant **exact** code snippet (max 10 lines) showing the vulnerability, starting from the line_number provided."
            },
            "recommendation": {
                "type": "string", 
                "description": "Detailed recommendation for fixing the vulnerability"
            },
            "cwe_id": {
                "type": "string",
                "description": "CWE ID if applicable (e.g., CWE-79)"
            }
        },
        "required": ["vulnerability_type", "severity", "affected_files", "line_number", "description", "code_snippet", "recommendation"]
    }
)

# Define the schema for the report_attack_path tool
report_attack_path_func = FunctionDeclaration(
    name="report_attack_path",
    description="Report a potential attack path chaining multiple vulnerabilities.",
    parameters={
        "type": "object",
        "properties": {
            "path_name": {
                "type": "string",
                "description": "A concise, descriptive name for the attack path (e.g., 'Unvalidated Redirect to XSS')."
            },
            "description": {
                "type": "string",
                "description": "A step-by-step explanation of how the vulnerabilities are chained together in this attack path."
            },
            "involved_vulnerabilities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List identifying the vulnerabilities involved in the chain (e.g., using 'Type @ File:Line')."
            },
            "overall_severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                "description": "The estimated overall severity of the successfully executed attack path."
            },
            "recommendation": {
                "type": "string",
                "description": "Recommendation for breaking the attack chain (e.g., fixing a specific vulnerability in the path)."
            }
        },
        "required": ["path_name", "description", "involved_vulnerabilities", "overall_severity", "recommendation"]
    }
)


class SecurityAnalyzer:
    def __init__(self, api_key, model="models/gemini-2.5-flash"): 
        genai.configure(api_key=api_key)
        self.model_name = model 
        self.tools = [Tool(function_declarations=[report_vulnerability_func, report_attack_path_func])]
        self.safety_settings = { 
            "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
            "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
            "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
            "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
        }
        self.tool_config = {"function_calling_config": "AUTO"}
        
        self.model = genai.GenerativeModel(
            model_name=self.model_name,
            safety_settings=self.safety_settings,
            tools=self.tools,
            tool_config=self.tool_config
        )
        
        # Import manifest parser for deeplink analysis
        from .manifest_parser import AndroidManifestParser
        self.manifest_parser = AndroidManifestParser()
        

    def analyze_code_for_category(self, code_chunks, category):
        """Analyze specific code chunks deeply for vulnerabilities using Gemini."""
        logger.debug(f"[Analysis] Preparing context and prompt for category: {category} on {len(code_chunks)} chunks")
        context = self._format_code_for_analysis(code_chunks)
        if not context:
            logger.debug(f"[Analysis] No relevant code chunks provided for category: {category}. Skipping analysis.")
            return [], None, None
        
        prompt = self._create_security_prompt(category, context)
        
        logger.debug(f"[Analysis] Calling Gemini model ({self.model_name}) for category: {category}...")
        vulnerabilities = []
        input_tokens = None
        output_tokens = None

        try:
            response = self.model.generate_content(prompt)
            logger.debug(f"[Analysis] Gemini API call successful for category: {category}")
            
            # Extract Token Counts
            try:
                # Attempt to extract token counts from the response's usage_metadata
                # This structure is common but might need adjustment based on exact Gemini API response
                if response.usage_metadata:
                    input_tokens = response.usage_metadata.prompt_token_count
                    output_tokens = response.usage_metadata.candidates_token_count
                    logger.debug(f"[Analysis] Tokens for category '{category}': Input={input_tokens}, Output={output_tokens}")
                else:
                     logger.debug(f"[Analysis] usage_metadata not found in Gemini response for category '{category}'. Token counts unavailable.")
            except AttributeError:
                logger.debug(f"[Analysis] Could not retrieve token usage attributes (prompt_token_count/candidates_token_count) from usage_metadata for category '{category}'.")
            except Exception as e:
                logger.debug(f"[Analysis] Error extracting token counts for category '{category}': {e}")

            # Extract tool calls (function calls in Gemini terminology)
            if response.candidates and response.candidates[0].content.parts:
                logger.debug(f"[Analysis] Processing {len(response.candidates[0].content.parts)} parts from Gemini response for category {category}")
                for part in response.candidates[0].content.parts:
                    if part.function_call and part.function_call.name == 'report_vulnerability':
                        logger.debug(f"[Analysis] Found report_vulnerability function call")
                        try:
                            vulnerability = dict(part.function_call.args)
                            vulnerabilities.append(vulnerability)
                            logger.debug(f"[Analysis] Successfully extracted vulnerability: {vulnerability.get('vulnerability_type', 'N/A')}")
                        except Exception as e:
                            logger.debug(f"[Analysis] Error processing function call arguments for category {category}: {e}")
                            logger.debug(f"[Analysis] Faulty arguments: {part.function_call.args}")
            else:
                if response.candidates and response.candidates[0].finish_reason != "STOP":
                     logger.debug(f"[Analysis] Gemini response potentially blocked or incomplete for category '{category}'. Finish Reason: {response.candidates[0].finish_reason}")
                else:
                    logger.debug(f"[Analysis] No function calls or valid parts found in Gemini response for category: {category}. Text response: {response.text if hasattr(response, 'text') else 'N/A'}")
                
        except Exception as e:
            logger.debug(f"[Analysis] Gemini API call failed for category {category}: {e}", exc_info=True) 
            return [], None, None

        if not vulnerabilities:
             logger.debug(f"[Analysis] No vulnerabilities reported by Gemini for category: {category}")
        else:
             logger.debug(f"[Analysis] Extracted {len(vulnerabilities)} vulnerabilities for category: {category}")

        return vulnerabilities, input_tokens, output_tokens
    
    def analyze_deeplink_with_manifest(self, code_chunks, repo_manager, vector_db):
        """
        Analyze deeplink vulnerabilities using manifest-first approach
        
        Args:
            code_chunks: All available code chunks (used as fallback)
            repo_manager: Repository manager for file access
            vector_db: Vector database for targeted retrieval
            
        Returns:
            Tuple of (vulnerabilities, input_tokens, output_tokens, manifest_info)
        """
        logger.info(f"[Deeplink Analysis] Starting manifest-based deeplink analysis")
        
        # Step 1: Find and parse AndroidManifest.xml
        manifest_path = self.manifest_parser.find_manifest_file(repo_manager)
        if not manifest_path:
            logger.info(f"[Deeplink Analysis] No AndroidManifest.xml found. Using fallback analysis.")
            return self.analyze_code_for_category(code_chunks, "deeplink") + (None,)
        
        # Step 2: Extract deeplink information from manifest
        manifest_info = self.manifest_parser.get_deeplink_analysis_summary(manifest_path)
        logger.info(f"[Deeplink Analysis] Found {manifest_info['total_deeplink_activities']} deeplink activities in manifest")
        
        if not manifest_info['has_deeplinks']:
            logger.info(f"[Deeplink Analysis] No deeplinks found in manifest. Skipping targeted analysis.")
            return [], None, None, manifest_info
        
        # Step 3: Get activity names for filename-based matching
        activity_names = list(manifest_info['deeplink_activities'].keys())
        logger.info(f"[Deeplink Analysis] Activity names for analysis: {activity_names}")
        
        # Step 4: Retrieve targeted code chunks using filename matching
        try:
            targeted_chunks = vector_db.retrieve_deeplink_relevant_code(
                activity_names=activity_names,
                n_results=100  # Increased since we're being more targeted
            )
            logger.info(f"[Deeplink Analysis] Retrieved {len(targeted_chunks)} targeted code chunks")
            
            # Log which files were actually found for debugging
            found_files = set(chunk.metadata.get('relative_path', '') for chunk in targeted_chunks)
            if found_files:
                logger.info(f"[Deeplink Analysis] Found code in files: {list(found_files)}")
            else:
                logger.warning(f"[Deeplink Analysis] No matching files found for activities: {activity_names}")
                
        except Exception as e:
            logger.error(f"[Deeplink Analysis] Error retrieving targeted chunks: {e}")
            # Fallback to traditional analysis
            logger.info(f"[Deeplink Analysis] Falling back to traditional deeplink analysis")
            return self.analyze_code_for_category(code_chunks, "deeplink") + (manifest_info,)
        
        if not targeted_chunks:
            logger.warning(f"[Deeplink Analysis] No relevant code chunks found. Using fallback analysis.")
            return self.analyze_code_for_category(code_chunks, "deeplink") + (manifest_info,)
        
        # Step 5: Create enhanced context with manifest information
        # Get the actual files found from the targeted chunks
        found_files = list(set(chunk.metadata.get('relative_path', '') for chunk in targeted_chunks))
        enhanced_context = self._create_deeplink_context_with_manifest(
            targeted_chunks, manifest_info, found_files
        )
        
        # Step 6: Analyze with enhanced prompt
        prompt = self._create_deeplink_security_prompt(enhanced_context, manifest_info)
        
        logger.debug(f"[Deeplink Analysis] Calling Gemini model for targeted deeplink analysis...")
        vulnerabilities = []
        input_tokens = None
        output_tokens = None

        try:
            response = self.model.generate_content(prompt)
            logger.debug(f"[Deeplink Analysis] Gemini API call successful")
            
            # Extract Token Counts
            try:
                if response.usage_metadata:
                    input_tokens = response.usage_metadata.prompt_token_count
                    output_tokens = response.usage_metadata.candidates_token_count
                    logger.debug(f"[Deeplink Analysis] Tokens: Input={input_tokens}, Output={output_tokens}")
            except Exception as e:
                logger.debug(f"[Deeplink Analysis] Error extracting token counts: {e}")

            # Extract vulnerabilities
            if response.candidates and response.candidates[0].content.parts:
                for part in response.candidates[0].content.parts:
                    if part.function_call and part.function_call.name == 'report_vulnerability':
                        try:
                            vulnerability = dict(part.function_call.args)
                            vulnerabilities.append(vulnerability)
                            logger.debug(f"[Deeplink Analysis] Found vulnerability: {vulnerability.get('vulnerability_type', 'N/A')}")
                        except Exception as e:
                            logger.debug(f"[Deeplink Analysis] Error processing vulnerability: {e}")
            else:
                logger.debug(f"[Deeplink Analysis] No vulnerabilities found in response")
                
        except Exception as e:
            logger.error(f"[Deeplink Analysis] Gemini API call failed: {e}", exc_info=True) 
            return [], None, None, manifest_info

        logger.info(f"[Deeplink Analysis] Analysis complete. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities, input_tokens, output_tokens, manifest_info
    
    def _create_deeplink_context_with_manifest(self, code_chunks, manifest_info, activity_files):
        """Create enhanced context combining code chunks with manifest information"""
        
        # Format manifest information
        manifest_context = f"""
# ANDROID MANIFEST ANALYSIS

## Deeplink Activities Found ({manifest_info['total_deeplink_activities']}):
"""
        for activity, filters in manifest_info['deeplink_activities'].items():
            manifest_context += f"\n### Activity: {activity}\n"
            for i, filter_info in enumerate(filters):
                manifest_context += f"Intent Filter {i+1}:\n"
                manifest_context += f"  - Actions: {', '.join(filter_info['actions'])}\n"
                manifest_context += f"  - Categories: {', '.join(filter_info['categories'])}\n"
                if filter_info['data']:
                    manifest_context += f"  - Data patterns:\n"
                    for data in filter_info['data']:
                        manifest_context += f"    * {data}\n"
        
        if manifest_info['schemes']:
            manifest_context += f"\n## Custom Schemes: {', '.join(manifest_info['schemes'])}\n"
        if manifest_info['hosts']:
            manifest_context += f"\n## Hosts: {', '.join(manifest_info['hosts'])}\n"
        
        manifest_context += f"\n## Activity Files Being Analyzed: {', '.join(activity_files)}\n"
        
        # Format code chunks
        code_context = self._format_code_for_analysis(code_chunks)
        
        return f"{manifest_context}\n\n# CODE ANALYSIS\n\n{code_context}"
    
    def _create_deeplink_security_prompt(self, enhanced_context, manifest_info):
        """Create specialized prompt for manifest-aware deeplink analysis"""
        
        return f"""
# Android Deeplink Security Analysis

You are an expert Android security auditor. You have been provided with AndroidManifest.xml analysis and the corresponding source code for activities that handle deeplinks.

## Context:
{enhanced_context}

## Your Task:
Perform a comprehensive security analysis focusing on deeplink vulnerabilities. You have manifest information showing exactly which activities handle deeplinks and their intent filter configurations.

## Focus Areas:
1. **Intent Filter Security:** Analyze the manifest intent filters and corresponding code for:
   - Missing android:exported restrictions
   - Overly broad intent patterns
   - Lack of permission requirements

2. **URI Validation:** In the activity code, look for:
   - Unvalidated URI parsing (getIntent().getData())
   - Missing scheme/host validation
   - Path traversal in URI paths
   - Query parameter injection

3. **Authentication/Authorization:** Check if deeplink handlers:
   - Bypass authentication checks
   - Allow unauthorized access to sensitive features
   - Leak sensitive data through deeplink parameters

4. **Data Handling:** Examine how deeplink data is processed:
   - Direct use of URI parameters without validation
   - Insecure data extraction from intents
   - Potential for data injection attacks

5. **Navigation Security:** Analyze deeplink navigation:
   - Uncontrolled redirects
   - Fragment injection
   - Activity hijacking through task affinity

## Instructions:
- Use the manifest information to understand the deeplink configuration
- Cross-reference with the source code to identify implementation vulnerabilities
- For EVERY vulnerability found, use the `report_vulnerability` tool
- Be specific about file locations and code snippets
- Consider the interaction between manifest declarations and code implementation
- Focus on demonstrable security issues, not theoretical possibilities

Only report vulnerabilities you are confident exist based on the code analysis.
"""
    
    def _format_code_for_analysis(self, code_chunks):
        """Format code chunks for Gemini analysis."""
        formatted_chunks = []
        
        for i, chunk in enumerate(code_chunks):
            content = chunk.page_content
            metadata = chunk.metadata
            
            formatted_chunk = f"""File: {metadata['relative_path']}
Language: {metadata['language']}
---
{content}
---
"""
            formatted_chunks.append(formatted_chunk)
            
        return "\n\n".join(formatted_chunks)
    
    def _create_security_prompt(self, category, context):
        """Create a specialized prompt for the security analysis using Gemini."""
        category_prompts = {
            "authentication": """
Analyze the provided code for authentication vulnerabilities. Focus specifically on:
1.  **Weak Authentication:** Are there hardcoded credentials, default passwords, lack of rate limiting on logins, or easily guessable secrets?
2.  **Credential Storage:** Are passwords or secrets stored insecurely (e.g., plain text, weak hashing like MD5/SHA1)? Look for hashing implementations.
3.  **Session Management:** Are session tokens generated securely? Are they vulnerable to fixation? Is logout functionality properly implemented (token invalidation)? Check token storage (localStorage vs secure cookies).
4.  **Password Reset:** Is the password reset mechanism secure? Does it rely on guessable tokens or leak information?
5.  **MFA/Authorization Checks:** Are critical actions protected by appropriate authorization checks? Is MFA implemented correctly if present?

For EVERY vulnerability found, use the `report_vulnerability` tool. Be precise about the affected file and code. Assess severity based on potential impact.
""",
            "injection": """
Analyze the provided code for injection vulnerabilities. Examine these specific areas carefully:
1.  **SQL Injection:** Look for user-controlled input used directly in SQL queries constructed with string formatting or concatenation. Check ORM usage for potential vulnerabilities (e.g., raw SQL execution with unsanitized input).
2.  **Command Injection:** Identify any instances where user input might be passed to shell commands or OS execution functions (e.g., `os.system`, `subprocess.run` with `shell=True`).
3.  **Cross-Site Scripting (XSS):** Check if user input is reflected in HTML output without proper sanitization or escaping. Look for use of `dangerouslySetInnerHTML` or similar functions in frontend code. Examine template engines for auto-escaping configurations.
4.  **Server-Side Template Injection (SSTI):** If template engines are used (e.g., Jinja2, Handlebars), check if user input can influence template structure or execute directives.
5.  **Untrusted Data Usage:** Scrutinize file operations (read/write), network calls (URLs), or redirects that might use unvalidated user input.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the injection point, the type of injection, and provide a specific recommendation.
""",

            "webview": """
Analyze the provided code for WebView vulnerabilities in Android. Examine these specific areas carefully:
1.  **Unsafe URI Loading:** Look for usage of WebView that does not validate the URI, host, or scheme before loading.
2.  **JavaScript Enabled:** Check if JavaScript is enabled unnecessarily, increasing attack surface.
3.  **addJavascriptInterface Usage:** Identify unsafe use of addJavascriptInterface, which can expose native methods.
4.  **File Access:** Look for WebView settings that allow file access or universal access from file URLs.
5.  **Untrusted Content:** Check if WebView loads content from untrusted sources or external input.
6.  **Improper WebViewClient/shouldOverrideUrlLoading:** Ensure proper use of WebViewClient and shouldOverrideUrlLoading to control navigation and prevent phishing or malicious redirects.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the WebView configuration, the risk, and the specific code location.
""",

            "deeplink": """
Analyze the provided code for deeplink vulnerabilities in Android. Examine these specific areas carefully:
1.  **Unprotected Intent Filters:** Look for intent filters that handle external input without proper protection (e.g., missing android:exported or permission).
2.  **Sensitive Actions:** Identify deeplinks that trigger sensitive actions without authentication or authorization checks.
3.  **Data Leakage:** Check if deeplinks expose sensitive data to other apps or external actors.
4.  **Hijacking/Phishing:** Look for patterns where deeplinks could be hijacked or used for phishing (e.g., by malicious apps).
5.  **Improper URI Parsing:** Ensure URIs are parsed and validated correctly to prevent manipulation.
6.  **Task Affinity/Launch Mode Issues:** Check for task affinity or launch mode configurations that could enable task hijacking.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the deeplink configuration, the risk, and the specific code location.
""",

            "path_traversal": """
Analyze the provided code for path traversal vulnerabilities specific to Android. Examine these specific areas carefully:
1.  **User Input in File Paths:** Look for user-controlled input used in file paths (e.g., openFileInput, FileInputStream, File, FileProvider).
2.  **Lack of Sanitization or Validation:** Check for missing validation or sanitization of file paths (e.g., "../" sequences, absolute paths).
3.  **Sensitive Directory Access:** Identify access to sensitive directories or files outside the intended app sandbox.
4.  **Insecure File Sharing:** Look for insecure file sharing via content URIs or external storage.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the path traversal vector, the risk, and the specific code location.
""",

            "intent": """
Analyze the provided code for intent vulnerabilities in Android. Examine these specific areas carefully:
1.  **Implicit Intents:** Look for use of implicit intents that could be intercepted by other apps.
2.  **Exported Components:** Check for exported activities, services, or broadcast receivers that may be unintentionally accessible.
3.  **Intent Spoofing:** Identify places where untrusted input is used to construct or handle intents.
4.  **Sensitive Data Exposure:** Check if sensitive data is passed via intents without proper protection.
5.  **PendingIntent Misuse:** Look for insecure use of PendingIntent, such as missing immutability or improper flags.
6.  **Broadcast Receiver Security:** Ensure broadcast receivers validate the sender and require permissions if needed.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the intent usage, the risk, and the specific code location.
""",

            "javascriptinterface": """
Analyze the provided code for JavaScript interface vulnerabilities in Android WebView. Examine these specific areas carefully:
1.  **addJavascriptInterface Exposure:** Look for use of addJavascriptInterface and ensure only trusted interfaces are exposed.
2.  **Untrusted JavaScript Execution:** Check if untrusted or external JavaScript can access exposed interfaces.
3.  **Sensitive Method Exposure:** Identify if sensitive or dangerous methods are exposed to JavaScript.
4.  **API Level Restrictions:** Ensure addJavascriptInterface is used safely, considering API level restrictions and security improvements in newer Android versions.
5.  **Input Validation:** Check if input from JavaScript to the interface is properly validated and sanitized.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the JavaScript interface exposure, the risk, and the specific code location.
""",
            "authorization": "Analyze for authorization issues like improper access control, missing checks, privilege escalation.",
            "data_protection": "Analyze for sensitive data exposure, insecure storage, or transmission of private information.",
            "api_security": "Analyze API endpoints for issues like insecure design, lack of authentication/authorization, rate limiting, etc.",
            "configuration": "Analyze for security misconfigurations in frameworks, servers, or dependencies."
        }
        
        base_prompt = f"""
# Security Analysis Task: {category.title()}

You are an expert security auditor using the Gemini language model. Your task is to perform a comprehensive security analysis of the provided web application code, focusing specifically on identifying vulnerabilities related to **{category}**.

## Code Context Provided:
This section contains a large context of code chunks relevant to the analysis category. Review it carefully.
{context}

## Your Task:
{category_prompts.get(category.lower(), f'Thoroughly analyze the provided code context for any potential **{category}** security vulnerabilities. For each distinct vulnerability you identify, you MUST use the `report_vulnerability` tool to document it.')}

## Important Guidelines for Analysis and Reporting:
1.  **Comprehensive Review:** Examine the entire provided code context. Consider interactions between different files and components if evident in the context.
2.  **Focus:** Concentrate on identifying vulnerabilities matching the `{category}` category description.
3.  **Tool Usage:** Use the `report_vulnerability` function tool for EVERY vulnerability found. Do not describe vulnerabilities in plain text only.
4.  **Tool Neutrality:** Do not mention specific static analysis tools like Semgrep. Focus only on the vulnerability and its remediation.
5.  **Accuracy:** Provide precise details in the tool arguments: affected file paths, the starting `line_number` of the vulnerability, a clear `description`, `severity` (Critical, High, Medium, Low, Informational), a specific `code_snippet` (max 10 lines starting from the line_number) demonstrating the issue, and actionable `recommendation`s for fixing it.
6.  **CWE ID:** Include the relevant CWE ID if applicable.
7.  **Prioritize:** Focus on clear, demonstrable vulnerabilities over highly speculative ones. If uncertain, note the uncertainty in the description field of the tool call.
8.  **No Chit-chat:** Only respond with tool calls. Do not add introductory or concluding remarks outside of the required tool function calls.
9.  **Be certain:** Only evaluate a code as vulnerable if you are very certain it is vulnerable. If you are not sure, do not report it as a vulnerability.
"""
        return base_prompt
