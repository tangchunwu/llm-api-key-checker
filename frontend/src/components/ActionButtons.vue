<template>
    <div class="actions-container">
        <div class="button-group-wrapper">
            <TransitionGroup name="button-fade">
                <!-- 开始检测按钮：当检测未进行时显示 -->
                <button v-if="!checkerStore.isChecking" key="start" id="checkButton" class="button primary"
                    @click="checkerStore.startCheck">
                    <span class="icon-play"></span>
                    开始检测
                </button>
                <!-- 控制按钮组：当检测进行中时显示 -->
                <template v-else>
                    <!-- 停止检测按钮 -->
                    <button key="stop" class="button stop" @click="checkerStore.stopCheck">
                        <span class="icon-stop"></span>
                        停止检测
                    </button>
                    <!-- 暂停检测按钮：当未暂停时显示 -->
                    <button v-if="!checkerStore.isPaused" key="pause" class="button pause" @click="checkerStore.pauseCheck">
                        <span class="icon-pause"></span>
                        暂停检测
                    </button>
                    <!-- 继续检测按钮：当已暂停时显示 -->
                    <button v-else key="resume" class="button resume" @click="checkerStore.resumeCheck">
                        <span class="icon-play"></span>
                        继续检测
                    </button>
                </template>
            </TransitionGroup>
        </div>
        <!-- 进度条和进度文本 -->
        <div id="progress-container" v-show="checkerStore.isChecking">
            <div class="progress-bar-wrapper"
                role="progressbar"
                :aria-valuenow="checkerStore.progress"
                aria-valuemin="0"
                aria-valuemax="100"
                :aria-label="`检测进度: ${checkerStore.progress}%`">
                <div id="progressBar" :style="{ width: checkerStore.progress + '%' }"></div>
            </div>
            <div id="progressText" aria-live="polite">
                <span>检测进度</span>
                <span>{{ checkerStore.completedCount }} / {{ checkerStore.totalTasks }} ({{ checkerStore.progress }}%)</span>
            </div>
        </div>
    </div>
</template>

<script setup>
import { useCheckerStore } from '@/stores/checker';

const checkerStore = useCheckerStore();
</script>

<style scoped>
    .actions-container {
        display: flex;
        flex-direction: column;
        gap: 16px;
    }

    .button-group-wrapper {
        display: flex;
        gap: 8px;
        width: 100%;
        position: relative;
        min-height: 44px;
    }

    .button {
        flex: 1;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    /* 按钮特定样式 */
    .button.stop {
        background: var(--accent-error);
    }

    .button.pause {
        background: var(--text-secondary);
    }

    .button.resume {
        background: var(--accent-success);
    }

    .button.stop:hover {
        background: var(--accent-error-hover);
        transform: translateY(-1px);
    }

    .button.pause:hover {
        background: var(--text-secondary-hover);
        transform: translateY(-1px);
    }

    .button.resume:hover {
        background: var(--accent-success-hover);
        transform: translateY(-1px);
    }

    /* 按钮图标 */
    [class^="icon-"]::before {
        margin-right: 8px;
        font-weight: bold;
    }

    .icon-play::before {
        content: '▶';
    }

    .icon-pause::before {
        content: '❚❚';
    }

    .icon-stop::before {
        content: '◼';
    }

    /* Vue TransitionGroup 动画 */
    .button-fade-enter-active,
    .button-fade-leave-active {
        transition: opacity 0.3s ease;
    }

    .button-fade-enter-from,
    .button-fade-leave-to {
        opacity: 0;
    }

    .button-fade-leave-active {
        position: absolute;
        width: calc(50% - 4px);
    }

    /* 进度条容器 */
    #progress-container {
        display: flex;
        flex-direction: column;
        gap: 8px;
        align-items: center;
        width: 100%;
        margin-top: 8px; /* 增加一点顶部间距 */
    }

    .progress-bar-wrapper {
        width: 100%;
        height: 14px; /* 增加高度 */
        background-color: var(--border-color-light); /* 更浅的背景 */
        border-radius: 7px;
        overflow: hidden;
        box-shadow: inset 0 1px 2px rgba(0,0,0,0.05); /* 内部阴影 */
    }

    #progressBar {
        width: 0%;
        height: 100%;
        background: var(--accent-primary);
        border-radius: 7px;
        transition: width 0.3s cubic-bezier(0.25, 0.8, 0.25, 1); /* 更平滑的过渡 */
        /* 可选：添加条纹效果（如果喜欢） */
        /* background-image: linear-gradient(45deg,rgba(255,255,255,.15) 25%,transparent 25%,transparent 50%,rgba(255,255,255,.15) 50%,rgba(255,255,255,.15) 75%,transparent 75%,transparent); */
        /* background-size: 1rem 1rem; */
    }

    #progressText {
        font-size: 0.85rem;
        font-weight: 500;
        font-family: var(--font-mono); /* 使用等宽字体显示数字 */
        color: var(--text-secondary);
        display: flex;
        justify-content: space-between;
        width: 100%;
        padding: 0 4px;
    }

    #progressText span {
        font-family: var(--font-sans);
    }
</style>