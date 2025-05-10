"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { Heart, Star, ArrowLeft, ArrowRight } from "lucide-react"

export default function MemoriesCard() {
    const [activeMemory, setActiveMemory] = useState(0)
    const memories = [
        "You always knew how to make me smile, even on my worst days.",
        "Your cooking has always been the best comfort in the world.",
        "The way you held my hand when I was scared gave me courage.",
        "Your love is the light that guides me through the darkest times.",
        "You taught me that kindness is the greatest strength.",
    ]

    return (
        <div className="flex flex-col items-center justify-center">
            <motion.div
                className="relative w-full max-w-sm mx-auto"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
            >
                <div className="relative rounded-2xl shadow-lg bg-gradient-to-br from-pink-100 to-purple-100 border-2 border-pink-200 p-6">
                    <motion.div
                        className="relative z-10 text-center"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.3 }}
                    >
                        <h2 className="text-3xl md:text-4xl font-bold mb-6 text-pink-600">Sweet Memories</h2>

                        <div className="relative h-32 mb-8 flex items-center justify-center bg-white bg-opacity-50 rounded-xl p-4 border border-pink-100">
                            <AnimatedMemory text={memories[activeMemory]} key={activeMemory} />
                        </div>

                        <div className="flex justify-center space-x-2 mb-6">
                            {memories.map((_, index) => (
                                <motion.button
                                    key={index}
                                    className={`w-3 h-3 rounded-full ${activeMemory === index ? "bg-pink-500" : "bg-pink-200"}`}
                                    whileHover={{ scale: 1.2 }}
                                    whileTap={{ scale: 0.9 }}
                                    onClick={() => setActiveMemory(index)}
                                />
                            ))}
                        </div>

                        <div className="flex justify-center space-x-4">
                            <motion.button
                                className="px-4 py-2 bg-gradient-to-r from-pink-400 to-purple-400 text-white rounded-full shadow-md hover:shadow-lg transition-all duration-300 flex items-center space-x-1"
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                onClick={() => setActiveMemory((prev) => (prev > 0 ? prev - 1 : memories.length - 1))}
                            >
                                <ArrowLeft size={16} />
                                <span>Previous</span>
                            </motion.button>

                            <motion.button
                                className="px-4 py-2 bg-gradient-to-r from-purple-400 to-pink-400 text-white rounded-full shadow-md hover:shadow-lg transition-all duration-300 flex items-center space-x-1"
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                onClick={() => setActiveMemory((prev) => (prev < memories.length - 1 ? prev + 1 : 0))}
                            >
                                <span>Next</span>
                                <ArrowRight size={16} />
                            </motion.button>
                        </div>
                    </motion.div>

                    {/* Decorative elements */}
                    <motion.div
                        className="absolute top-4 right-4 text-pink-400"
                        animate={{
                            rotate: [0, 10, -10, 0],
                        }}
                        transition={{
                            duration: 4,
                            repeat: Number.POSITIVE_INFINITY,
                            repeatType: "loop",
                        }}
                    >
                        <Star size={24} fill="currentColor" />
                    </motion.div>

                    <motion.div
                        className="absolute bottom-4 left-4 text-pink-400"
                        animate={{
                            rotate: [0, -10, 10, 0],
                        }}
                        transition={{
                            duration: 4,
                            repeat: Number.POSITIVE_INFINITY,
                            repeatType: "loop",
                            delay: 1,
                        }}
                    >
                        <Heart size={24} fill="currentColor" />
                    </motion.div>
                </div>
            </motion.div>
        </div>
    )
}

function AnimatedMemory({ text }) {
    return (
        <motion.div
            className="absolute inset-0 flex items-center justify-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.5 }}
        >
            <p className="text-purple-800 text-lg text-center">{text}</p>
        </motion.div>
    )
}
