// SPDX-License-Identifier: GPL-2.0-only

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

static constexpr unsigned MaxErrno = 4095;
static constexpr unsigned MaxValueDepth = 64;

// XXX, here, I believe, we follow the chain to see if this was casted from a pointer
static const Value *convertedPointer(const Value *V)
{
	for (unsigned Depth = 0; V && Depth < MaxValueDepth; Depth++) {
		if (auto *C = dyn_cast<PtrToIntInst>(V))
			return C->getPointerOperand();
		if (auto *C = dyn_cast<CastInst>(V)) {
			V = C->getOperand(0);
			continue;
		}
		break;
	}
	return nullptr;
}

static bool matchesPointer(const Value *V, const Value *Pointer)
{
	return V == Pointer || convertedPointer(V) == Pointer;
}

static const ConstantInt *comparisonThreshold(const Value *V)
{
	if (auto *C = dyn_cast<ConstantInt>(V))
		return C;
	if (auto *Expr = dyn_cast<ConstantExpr>(V))
		if (Expr->getOpcode() == Instruction::IntToPtr)
			return dyn_cast<ConstantInt>(Expr->getOperand(0));
	return nullptr;
}

static bool conditionImpliesIsErr(Value *Condition, bool Truth, const Value *Pointer)
{
	auto *Cmp = dyn_cast<ICmpInst>(Condition);
	CmpInst::Predicate Pred;
	const Value *Integer;
	const ConstantInt *Threshold;
	APInt Limit;

	if (!Cmp)
		return false;
	Pred = Cmp->getPredicate();
	Integer = Cmp->getOperand(0);
	Threshold = comparisonThreshold(Cmp->getOperand(1));
	if (!matchesPointer(Integer, Pointer)) {
		Integer = Cmp->getOperand(1);
		Threshold = comparisonThreshold(Cmp->getOperand(0));
		Pred = CmpInst::getSwappedPredicate(Pred);
	}
	if (!Threshold || !matchesPointer(Integer, Pointer))
		return false;
	if (Threshold->getBitWidth() != 32 && Threshold->getBitWidth() != 64)
		return false;
	if (!Truth)
		Pred = CmpInst::getInversePredicate(Pred);
	if (Pred != CmpInst::ICMP_UGE && Pred != CmpInst::ICMP_UGT)
		return false;

	Limit = APInt(Threshold->getBitWidth(), 0) -
		APInt(Threshold->getBitWidth(), MaxErrno);
	if (Pred == CmpInst::ICMP_UGT)
		--Limit;
	return Threshold->getValue().uge(Limit);
}

// XXX this is we are checking if (IS_ERR(ptr)) --> return PTR_ERR(ptr), but how?
static bool dominatedByIsErr(const Value *V, BasicBlock *BB, DominatorTree &DT)
{
	const Value *Pointer = convertedPointer(V);

	if (!Pointer)
		return false;

	while (BB) {
		BasicBlock *Dom = DT.getNode(BB)->getIDom() ?
			DT.getNode(BB)->getIDom()->getBlock() : nullptr;
		auto *Branch = Dom ? dyn_cast<BranchInst>(Dom->getTerminator()) : nullptr;
		bool TruePath, FalsePath;

		if (!Dom)
			break;
		if (!Branch || !Branch->isConditional()) {
			BB = Dom;
			continue;
		}
		TruePath = DT.dominates(Branch->getSuccessor(0), BB);
		FalsePath = DT.dominates(Branch->getSuccessor(1), BB);
		if (TruePath != FalsePath &&
		    conditionImpliesIsErr(Branch->getCondition(), TruePath, Pointer))
			return true;
		BB = Dom;
	}
	return false;
}

// is Range in [-4095, 0) ?
static bool isErrnoRange(const ConstantRange &Range)
{
	unsigned Width = Range.getBitWidth();

	if (Width != 32 && Width != 64)
		return false;

	auto L = APInt(Width, 0) - APInt(Width, MaxErrno);
	auto R = APInt(Width, 0);
	return !Range.isEmptySet() && ConstantRange(L, R).contains(Range);
}

static bool rangeAtUseIsErrno(const Use &U, LazyValueInfo &LVI)
{
	Value *V = U.get();

	return V->getType()->isIntegerTy() &&
	       isErrnoRange(LVI.getConstantRangeAtUse(U, false));
}

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

static bool functionHasCleanErrnoPath(Function &F, LazyValueInfo &LVI, DominatorTree &DT)
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

		if (rangeAtUseIsErrno(Return->getOperandUse(0), LVI) ||
		    isErrnoConstant(Return->getReturnValue()) ||
		    dominatedByIsErr(Return->getReturnValue(), BB, DT))
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
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
	{
		// LTO can run this twice, do a smarter processing later,
		// for now do not duplicate the section
		if (M.getNamedMetadata("fmodret_candidates.done"))
			return PreservedAnalyses::all();

		SmallVector<Constant *> Fns; // XXX: why small vector? Is 10K small?
		auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

		for (Function &F : M) {
			if (F.isDeclaration() ||
			    F.hasWeakAnyLinkage() || // to be removed later when we can track __weak properly
			    F.hasAvailableExternallyLinkage() ||
			    !F.getReturnType()->isIntegerTy())
				continue;

			unsigned Width = F.getReturnType()->getIntegerBitWidth();
			if (Width != 32 && Width != 64)
				continue;

			auto &LVI = FAM.getResult<LazyValueAnalysis>(F);
			auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);
			if (functionHasCleanErrnoPath(F, LVI, DT))
				Fns.push_back(&F);
		}

		if (Fns.empty())
			return PreservedAnalyses::all();

		emitCandidates(M, Fns);
		M.getOrInsertNamedMetadata("fmodret_candidates.done");

		PreservedAnalyses PA;
		PA.preserve<FunctionAnalysisManagerModuleProxy>();
		PA.preserveSet<CFGAnalyses>();
		PA.preserve<LazyValueAnalysis>();
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
