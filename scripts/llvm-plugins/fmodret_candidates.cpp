// SPDX-License-Identifier: GPL-2.0-only
/* LLVM plugin infrastructure for collecting fmod_ret candidate metadata. */

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace {

class FmodretCandidatesPass : public PassInfoMixin<FmodretCandidatesPass> {
public:
	PreservedAnalyses run(Module &, ModuleAnalysisManager &)
	{
		return PreservedAnalyses::all();
	}
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {LLVM_PLUGIN_API_VERSION, "fmodret-candidates", "1.0",
		[](PassBuilder &PB) {
			PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel,
				   ThinOrFullLTOPhase) {
					MPM.addPass(FmodretCandidatesPass());
				});
		}};
}
