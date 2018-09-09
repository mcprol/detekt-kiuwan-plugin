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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.jetbrains.kotlin.org.jline.utils.Log;

import io.gitlab.arturbosch.detekt.api.BaseRule;
import io.gitlab.arturbosch.detekt.api.Config;
import io.gitlab.arturbosch.detekt.api.RuleSet;
import io.gitlab.arturbosch.detekt.api.RuleSetProvider;


/**
 * @author mcprol
 */
public class DetektFakeRuleSetProvider implements RuleSetProvider {

	private String rulesetId;
	private List<BaseRule> rulesToRun;		
	private RuleSet ruleset;

	public DetektFakeRuleSetProvider(String rulesetId, Collection<BaseRule> detektRulesToRun) {
		Log.warn("FakeRuleSetProvider.FakeRuleSetProvider()");
		this.rulesetId = rulesetId;
		this.rulesToRun = new ArrayList<>(detektRulesToRun);
	}

	@Override
	public RuleSet buildRuleset(Config config) {
		Log.warn("FakeRuleSetProvider.buildRuleset()");

		if (null == ruleset) {
			ruleset = new RuleSet(rulesetId, rulesToRun);
		}

		return ruleset;
	}

	@Override
	public String getRuleSetId() {
		return rulesetId;
	}

	@Override
	public RuleSet instance(Config config) {
		Log.warn("FakeRuleSetProvider.instance()");

		if (null == ruleset) {
			ruleset = buildRuleset(Config.Companion.getEmpty());
		}

		return ruleset;
	}		
}


