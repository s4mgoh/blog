<template>
  <div class="filters-box border border-[--secondary-bg] rounded-lg bg-[--primary-bg-transparent-80] p mb-5">
    <button @click="toggle" class="flex justify-between w-full p-5 text-left">
      <h3>Filters</h3>
      <i
        class="transition-transform duration-300 ease-in-out my-auto text-sm text-white fa-regular fa-chevron-down"
        :class="{ 'rotate-180': isOpen }"
      ></i>
    </button>
    <transition
      name="expand"
      @enter="enter"
      @after-enter="afterEnter"
      @leave="leave"
    >
      <div v-if="isOpen" class="overflow-hidden">
        <div class="px-5 pb-5">
          <div class="pt-3 select-none border-t border-[--secondary-bg]">
            <h5>Categories</h5>
            <div class="flex flex-wrap justify-start gap-3 pt-2 pb-3 text-md">
              <slot name="categories"></slot>
            </div>
            <h5>Years</h5>
            <div class="flex flex-wrap justify-start gap-3 pt-2 text-md">
              <slot name="years"></slot>
            </div>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const isOpen = ref(true);

const toggle = () => {
  isOpen.value = !isOpen.value;
};

const enter = (element) => {
  element.style.height = 'auto';
  const height = getComputedStyle(element).height;
  element.style.height = '0';
  requestAnimationFrame(() => {
    element.style.height = height;
  });
};

const afterEnter = (element) => {
  element.style.height = 'auto';
};

const leave = (element) => {
  element.style.height = getComputedStyle(element).height;
  requestAnimationFrame(() => {
    element.style.height = '0';
  });
};
</script>

<style>
.expand-enter-active,
.expand-leave-active {
  transition: height 0.3s ease-in-out;
}
</style>
