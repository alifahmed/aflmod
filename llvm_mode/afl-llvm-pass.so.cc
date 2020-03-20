/*
 Copyright 2015 Google LLC All rights reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at:

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

/*
 american fuzzy lop - LLVM-mode instrumentation pass
 ---------------------------------------------------

 Written by Laszlo Szekeres <lszekeres@google.com> and
 Michal Zalewski <lcamtuf@google.com>

 LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
 from afl-as.c are Michal's fault.

 This library is plugged into LLVM when invoking clang through afl-clang-fast.
 It tells the compiler to add code roughly equivalent to the bits discussed
 in ../afl-as.h.
 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace {

class AFLCoverage: public ModulePass {

public:

	static char ID;
	AFLCoverage() :
			ModulePass(ID) {
	}

	bool runOnModule(Module &M) override;

	// StringRef getPassName() const override {
	//  return "American Fuzzy Lop Instrumentation";
	// }

};

}

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M) {
  LLVMContext &C = M.getContext();

  IntegerType *   Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *   Int32Ty = IntegerType::getInt32Ty(C);

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST " by <lszekeres@google.com>\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *       inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLIdxPtr =
        new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_idx_ptr");

  GlobalVariable *AFLPrevLoc1 = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc1", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  GlobalVariable *AFLPrevLoc2 = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc2", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);

  GlobalVariable *AFLPrevLoc3 = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc3", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M){
  		std::vector<BasicBlock::iterator> ips;
  		for(auto &bb : F){
  			ips.push_back(bb.getFirstInsertionPt());
  		}

  		for (auto &IP : ips) {

  			//BasicBlock::iterator IP = BB.getFirstInsertionPt();
  			//Instruction * firstInstOrig = &(*IP);
  			IRBuilder<> IRB(&(*IP));

  			if (AFL_R(100) >= inst_ratio)
  				continue;

  			/* Make up cur_loc */

  			unsigned int cur_loc = AFL_R(MAP_SIZE);
  			while((cur_loc ^ (cur_loc >> 1)) == 0){
  				cur_loc = AFL_R(MAP_SIZE);
  			}

  			ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

  			/* Load prev_loc */
  			LoadInst *PrevLoc1 = IRB.CreateLoad(AFLPrevLoc1);
  			PrevLoc1->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			LoadInst *PrevLoc2 = IRB.CreateLoad(AFLPrevLoc2);
  			PrevLoc2->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			LoadInst *PrevLoc3 = IRB.CreateLoad(AFLPrevLoc3);
  			PrevLoc3->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  			Value* key = IRB.CreateXor(IRB.CreateXor(PrevLoc1, PrevLoc2), IRB.CreateXor(PrevLoc3, CurLoc));
  			IRB.CreateStore(PrevLoc2, AFLPrevLoc3)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			IRB.CreateStore(PrevLoc1, AFLPrevLoc2)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc1)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  			/*load idx*/
  			LoadInst *IdxPtr = IRB.CreateLoad(AFLIdxPtr);
  			IdxPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			Value *idxAddr = IRB.CreateGEP(Int32Ty, IdxPtr, key);

  			//load index value
  			LoadInst* idxVal = IRB.CreateLoad(idxAddr);
  			idxVal->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  			//check if index value is -1
  			Value* cond = IRB.CreateICmpEQ(ConstantInt::get(Int32Ty, -1), idxVal);

  			//create then block
  			Instruction* then = SplitBlockAndInsertIfThen(cond, &(*IP), false, MDBuilder(C).createBranchWeights(1, 100000));
  			assert(dyn_cast<BranchInst>(then)->isUnconditional());

  			//instrument then block
  			IRB.SetInsertPoint(then);
  			LoadInst* cntVal = IRB.CreateLoad(IdxPtr);
  			cntVal->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			IRB.CreateStore(cntVal, idxAddr)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			IRB.CreateStore(IRB.CreateAdd(cntVal, ConstantInt::get(Int32Ty, 1)), IdxPtr)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));


  			//instrument tail
  			IRB.SetInsertPoint(&(*IP));
  			PHINode* idx = IRB.CreatePHI(Int32Ty, 2);
  			idx->addIncoming(idxVal, idxVal->getParent());
  			idx->addIncoming(cntVal, cntVal->getParent());

  			LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
  			MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			Value *mapAddr = IRB.CreateGEP(Int8Ty, MapPtr, idx);

  			LoadInst *mapVal = IRB.CreateLoad(mapAddr);
  			mapVal->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
  			IRB.CreateStore(IRB.CreateAdd(mapVal, ConstantInt::get(Int8Ty, 1)), mapAddr)->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  			inst_blocks++;

  		}
  	}

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
          getenv("AFL_HARDEN")
              ? "hardened"
              : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                     ? "ASAN/MSAN"
                     : "non-hardened"),
          inst_ratio);

  }

  return true;

}

static void registerAFLPass(const PassManagerBuilder&,
		legacy::PassManagerBase &PM) {

	PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
		PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
		PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
