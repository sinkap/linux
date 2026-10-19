// SPDX-License-Identifier: GPL-2.0-only

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

static constexpr unsigned MaxErrno = 4095;

static bool isErrnoConstant(const Value *V)
{
	auto *C = dyn_cast<ConstantInt>(V);
	int64_t N;

	if (!C || (C->getBitWidth() != 32 && C->getBitWidth() != 64))
		return false;

	N = C->getSExtValue();
	return N >= -MaxErrno && N < 0;
}

// XXX: I still do not understand precisely what it does
static bool isCleanInstruction(const Instruction &I)
{
	if (auto *Intrinsic = dyn_cast<IntrinsicInst>(&I)) {
		switch (Intrinsic->getIntrinsicID()) {
		case Intrinsic::assume:
		case Intrinsic::lifetime_start:
		case Intrinsic::lifetime_end:
		case Intrinsic::invariant_start:
		case Intrinsic::invariant_end:
			return true;
		default:
			break;
		}
	}
	return !I.mayHaveSideEffects();
}

static bool cleanBB(BasicBlock *BB)
{
	for (Instruction &I : *BB) {
		if (!isCleanInstruction(I))
			return false;
	}
	return true;
}

static bool functionHasCleanErrnoPath(Function &F)
{
	SmallPtrSet<BasicBlock *, 32> CleanEntries; // XXX: don't like 32
	SmallPtrSet<BasicBlock *, 32> CleanBBs;
	SmallVector<BasicBlock *, 32> Worklist;

	// build the list of "clean" BBs
	CleanEntries.insert(&F.getEntryBlock());
	Worklist.push_back(&F.getEntryBlock());
	while (!Worklist.empty()) {
		BasicBlock *BB = Worklist.pop_back_val();
		if (!cleanBB(BB))
			continue;

		CleanBBs.insert(BB);

		for (BasicBlock *Successor : successors(BB)) {
			auto havent_seen = CleanEntries.insert(Successor).second;
			if (havent_seen)
				Worklist.push_back(Successor);
		}
	}

	// consider the return values of "clean" exits, i.e.,
	// exits, where all predcessors were "clean"
	for (BasicBlock *BB : CleanBBs) {
		auto *Return = dyn_cast<ReturnInst>(BB->getTerminator());
		if (!Return || !Return->getReturnValue())
			continue;

		if (isErrnoConstant(Return->getReturnValue()))
			return true;
	}
	return false;
}

static void emitCandidates(Module &M, ArrayRef<Constant *> Fns)
{
	auto *PtrTy = PointerType::getUnqual(M.getContext());
	auto *ArrTy = ArrayType::get(PtrTy, Fns.size());
	auto isConstant = true;
	auto *GV = new GlobalVariable(M, ArrTy, isConstant, // XXX: does this approach allow us to pass more information and also more complex structures to allow to check how error propagations work?
				      GlobalValue::PrivateLinkage,
				      ConstantArray::get(ArrTy, Fns),
				      "fmodret_candidates.table");
	GV->setSection(".BTF_fmodret_candidates");
	GV->setAlignment(M.getDataLayout().getPointerABIAlignment(0));
	appendToUsed(M, {GV});
}

class FmodretCandidatesPass : public PassInfoMixin<FmodretCandidatesPass>
{
public:
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &)
	{
		// LTO can run this twice, do a smarter processing later,
		// for now do not duplicate the section
		if (M.getNamedMetadata("fmodret_candidates.done"))
			return PreservedAnalyses::all();

		SmallVector<Constant *> Fns; // XXX: why small vector? Is 10K small?

		for (Function &F : M) {
			if (F.isDeclaration() ||
			    F.hasWeakAnyLinkage() || // to be removed later when we can track __weak properly
			    F.hasAvailableExternallyLinkage() ||
			    !F.getReturnType()->isIntegerTy())
				continue;

			unsigned Width = F.getReturnType()->getIntegerBitWidth();
			if (Width != 32 && Width != 64)
				continue;

			if (functionHasCleanErrnoPath(F))
				Fns.push_back(&F);
		}

		if (Fns.empty())
			return PreservedAnalyses::all();

		emitCandidates(M, Fns);
		M.getOrInsertNamedMetadata("fmodret_candidates.done");

		PreservedAnalyses PA;
		PA.preserveSet<CFGAnalyses>();
		return PA;
	}

	static bool isRequired() { return true; }
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {
		LLVM_PLUGIN_API_VERSION,
		"fmodret-candidates",
		"1.0",
		[](PassBuilder &PB) {
			PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
					MPM.addPass(FmodretCandidatesPass());
				   }
			);
		}
	};
}
