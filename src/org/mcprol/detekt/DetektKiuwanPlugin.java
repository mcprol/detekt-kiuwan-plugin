// MIT License
//
// Copyright (c) 2018 Marcos Cacabelos Prol
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package org.mcprol.detekt;

import java.io.File;
import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

import org.jetbrains.kotlin.org.jline.utils.Log;

import com.als.core.AbstractRule;
import com.als.core.RuleContext;
import com.als.core.RuleViolation;
import com.als.core.ast.BaseNode;
import com.als.core.io.CodeContents;
import com.als.core.io.FileContents;

import io.gitlab.arturbosch.detekt.api.BaseRule;
import io.gitlab.arturbosch.detekt.api.Config;
import io.gitlab.arturbosch.detekt.api.Detektion;
import io.gitlab.arturbosch.detekt.api.FileProcessListener;
import io.gitlab.arturbosch.detekt.api.Finding;
import io.gitlab.arturbosch.detekt.api.Issue;
import io.gitlab.arturbosch.detekt.api.RuleSetProvider;
import io.gitlab.arturbosch.detekt.core.DetektFacade;
import io.gitlab.arturbosch.detekt.core.Detektor;
import io.gitlab.arturbosch.detekt.core.FileProcessorLocator;
import io.gitlab.arturbosch.detekt.core.PathFilter;
import io.gitlab.arturbosch.detekt.core.ProcessingSettings;
import io.gitlab.arturbosch.detekt.core.RuleSetLocator;


/**
 * @author mcprol
 */
public class DetektKiuwanPlugin extends AbstractRule { 
	
	private static boolean detektWasInitialized = false;
	private static boolean detektWasExecuted = false;
	
	private static ProcessingSettings detektProcessingSettings = null;
	private static RuleSetLocator detektRuleSetLocator = null;
	private static List<RuleSetProvider> detektRuleSetProviders = null;
	private static Map<String, BaseRule> detektRulesToRun = new LinkedHashMap<>();
	private static Map<String, DetektKiuwanPlugin> kiuwanRulesToRun = new LinkedHashMap<>();

	public void initialize (RuleContext ctx) { 
		super.initialize(ctx);
		
		this.getLogger().debug("initialize " +  this.getName());
		if (!detektWasInitialized) {
			detektWasInitialized = true;
			detektInitializer(ctx);
		}
		
		registerRule(getDetektRuleId());
	}


	
	protected void visit (BaseNode root, final RuleContext ctx) { 
		//this.getLogger().debug("visit " + this.getClass().getName() + ", " + this.getName());
	}
	
	
	public void postProcess (RuleContext ctx) { 
		super.postProcess(ctx); 
		this.getLogger().debug("postProcess " +  this.getName());

		if (!detektWasExecuted) {
			detektWasExecuted = true;

			// runs detekt.
			this.getLogger().debug("Executing 'detekt' engine ...");
			DetektFacade detektFacade = this.createDetektExecutor();
			Detektion detektion = detektFacade.run();
			this.getLogger().debug("... 'detekt' engine executed.");
			
			Map<String, List<Finding>> findings = detektion.getFindings();
			createRuleViolations(ctx, findings);
		}	
	}


	private void detektInitializer(RuleContext ctx) {
		detektProcessingSettings = createProcessingSettings(ctx.getBaseDirs());
		detektRuleSetLocator = new RuleSetLocator(detektProcessingSettings);
		detektRuleSetProviders = detektRuleSetLocator.load();
	}


	private void registerRule(String ruleToRun) {
		this.getLogger().info("Register kiuwan rule '" +  this.getName() + "' in detekt...");
		detektRuleSetProviders.forEach(rsp -> {
			if (!detektRulesToRun.containsKey(ruleToRun)) {
				this.getLogger().debug("Looking for 'detekt' rule with name '" + ruleToRun + "' in ruleset '" + rsp.getRuleSetId() + "' ...");
				List<BaseRule> rules = rsp.buildRuleset(Config.Companion.getEmpty()).getRules();

				Optional<BaseRule> matchingObject = rules.stream().filter(r -> r.getId().equals(ruleToRun)).findFirst();
				BaseRule detektRule = matchingObject.orElse(null);
				
				if (null != detektRule) {
					this.getLogger().debug("... found.");
					detektRulesToRun.put(ruleToRun, detektRule);
					kiuwanRulesToRun.put(ruleToRun, this);
				}
			}
		});
					
		if (!detektRulesToRun.containsKey(ruleToRun)) {
			this.getLogger().error("Not found 'detekt' rule with name '" + ruleToRun + "'.");
		}
	}
		

	private void createRuleViolations(RuleContext ctx, Map<String, List<Finding>> findings) {
		this.getLogger().debug("Add violations for 'detekt' findings (" + findings.size() + ") ...");
		for (String key: findings.keySet()) {
			List<Finding> list = findings.get(key);
			this.getLogger().debug("Add violations for key '" + key + "' (" + list.size() + ") ...");
			list.forEach(f -> {
				dumpFinding(f);
				Issue issue = f.getIssue();
				String detektRuleId = issue.getId();
				DetektKiuwanPlugin kiuwanRule = kiuwanRulesToRun.get(detektRuleId);
				if (null != kiuwanRule) {
					//RuleViolation rv = createRuleViolation(ctx, f);
					RuleViolation rv = createRuleViolation(ctx, f, kiuwanRule);
					ctx.getReport().addRuleViolation(rv);
					this.getLogger().debug("... add RuleViolation for 'detekt' finding for rule '" + detektRuleId + "'.");
				} else {
					this.getLogger().debug("... skip 'detekt' finding for rule '" + detektRuleId + "'.");
				}
			});
		}
		this.getLogger().debug("... 'detekt' findings added.");
	}

	
	private RuleViolation createRuleViolation(RuleContext ctx, Finding finding) {
		File srcFile = new File(finding.getFile());
		int lineNumber = finding.getStartPosition().getLine();
		String lineCode = null;
		
		FileContents fc = CodeContents.build(srcFile, FileContents.DEFAULT_ENCODING);
		if (fc!=null) {
			lineCode = fc.getLine(lineNumber-1);
		}
		
		RuleViolation rv = createRuleViolation(srcFile, finding.getStartPosition().getLine(), finding.getIssue().getId(), lineCode);
		
		return rv;
	}
	
	
	private RuleViolation createRuleViolation(RuleContext ctx, Finding finding, DetektKiuwanPlugin kiuwanRule) {
		File srcFile = new File(finding.getFile());
		int lineNumber = finding.getStartPosition().getLine();
		String lineCode = null;
		
		FileContents fc = CodeContents.build(srcFile, FileContents.DEFAULT_ENCODING);
		if (fc!=null) {
			lineCode = fc.getLine(lineNumber-1);
		}
		
		RuleViolation rv = new RuleViolation(kiuwanRule, lineNumber, srcFile);
		rv.setCodeViolated(lineCode);
		rv.setExplanation(finding.getIssue().getId());
		
		return rv;
	}


	private void dumpFinding(Finding f) {
		Log.warn("\n\n\nFinding: --------------------------");
		//Log.warn("Finding: " + f.toString());
		Log.warn("getFile(): " + f.getFile());
		Log.warn("getId(): " + f.getId());
		Log.warn("getInClass(): " + f.getInClass());
		//Log.warn("getLocationAsString(): " + f.getLocationAsString());
		Log.warn("getMessage(): " + f.getMessage());
		Log.warn("getName(): " + f.getName());
		Log.warn("getSignature(): " + f.getSignature());
		Log.warn("getCharPosition(): " + f.getCharPosition());
		//Log.warn("getEntity(): " + f.getEntity());
		Log.warn("getIssue(): " + f.getIssue());
		//Log.warn("getLocation(): " + f.getLocation());
		Log.warn("getStartPosition(): " + f.getStartPosition());	
	}

	
	private DetektFacade createDetektExecutor() {
		//List<RuleSetProvider> providers = createRuleSetProviders(detektProcessingSettings, detektRulesToRun);
		List<RuleSetProvider> providers = createRuleSetProviders(detektProcessingSettings);

		FileProcessorLocator fileProcessorLocator = new FileProcessorLocator(detektProcessingSettings);
		List<FileProcessListener> processors = fileProcessorLocator.load();
		
		Detektor detektor = new Detektor(detektProcessingSettings, providers, processors);
		
		DetektFacade detektFacade = new DetektFacade(detektor, detektProcessingSettings, processors);
		
		return detektFacade;
	}
	
	
	private String getDetektRuleId() {
		String kiuwanRuleId = this.getName();
		
		String[] tokens = kiuwanRuleId.split("\\.");

		return tokens[tokens.length-1];
	}


	private List<RuleSetProvider> createRuleSetProviders(ProcessingSettings settings, Map<String, BaseRule> detektRulesToRun) {
		this.getLogger().debug("createRuleSetProviders() with rules: " + detektRulesToRun.values());
		DetektFakeRuleSetProvider fakeRuleSetProvider = new DetektFakeRuleSetProvider("fakerulesetprovider", detektRulesToRun.values());

		List<RuleSetProvider> fakeRuleSetProviders = new ArrayList<>();
		fakeRuleSetProviders.add(fakeRuleSetProvider);
		
		return fakeRuleSetProviders;	
	}


	private List<RuleSetProvider> createRuleSetProviders(ProcessingSettings settings) {
		RuleSetLocator ruleSetLocator = new RuleSetLocator(settings);
		List<RuleSetProvider> ruleSetProviders = ruleSetLocator.load();
		
		return ruleSetProviders;
	}


	private ProcessingSettings createProcessingSettings(List<File> basedirs) {		
		List<Path> srcdirs = basedirs.stream().map(f -> Paths.get(f.getAbsolutePath())).collect(Collectors.toList()); 

		Config config = Config.Companion.getEmpty();
		List<PathFilter> pathFilters = new ArrayList<>();
		Boolean parallelCompilation = Boolean.FALSE;
		Boolean excludeDefaultRuleSets = Boolean.FALSE;
		List<Path> pluginPaths = new ArrayList<>();
		ExecutorService executorService = null;
		PrintStream errorPrinter = System.out;		
		
		
		ProcessingSettings settings = new ProcessingSettings(srcdirs, config, pathFilters, parallelCompilation, excludeDefaultRuleSets, pluginPaths, executorService, errorPrinter);
		
		return settings;
	}
	
}

